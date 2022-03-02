from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from karton.core import Karton, RemoteResource, Task
from mwdblib import MWDB, MWDBBlob, MWDBConfig, MWDBObject
from mwdblib.api.options import APIClientOptions

from .__version__ import __version__


class MWDBReporter(Karton):
    """
    Uploads analysis artifacts to MWDB (ripped samples and static configurations).

    Expected incoming task structure for samples:
    ```
    {
        "headers": {
            "type": "sample",
            "stage": "recognized" (to be processed) or "analyzed" (final artifact)
            "kind": all but not "raw", must have known type or be checked first by "karton.classifier"
            "platform": optional target platform
            "extension": optional file type extension
        },
        "payload": {
            "sample": Resource with sample contents
            "parent": optional, Resource with parent sample contents
            "tags": optional, list of additional tags to be added
            "attributes": optional, dict with attributes to be added
            "comments": optional, list of comments to be added (legacy alias: "additional_info")
        }
    }
    ```

    Samples are decorated with tag: ``kind:platform:extension`` or ``misc:kind`` if platform is missing

    Expected incoming task structure for configs:
    ```
    {
        "headers": {
            "type": "config",
            "family": <malware family>
        },
        "payload": {
            "sample": Resource with **original** sample contents
            "parent": optional, Resource with **unpacked** sample/dump contents
            "tags": optional, list of additional tags to be added
            "attributes": optional, dict with attributes to be added
            "comments": optional, list of comments to be added (legacy alias: "additional_info")
        }
    }
    ```
    """  # noqa

    identity = "karton.mwdb-reporter"
    version = __version__
    filters = [
        {"type": "sample", "stage": "recognized"},
        {"type": "sample", "stage": "analyzed"},
        {"type": "config"},
        {"type": "blob"},
    ]
    MAX_FILE_SIZE = 1024 * 1024 * 40

    def _get_mwdb(self) -> MWDB:
        mwdb_config = dict(self.config.config.items("mwdb"))
        mwdb = MWDB(
            api_key=mwdb_config.get("api_key"),
            api_url=mwdb_config.get("api_url", APIClientOptions.api_url),
            retry_on_downtime=True,
        )
        if not mwdb.api.auth_token:
            mwdb.login(mwdb_config["username"], mwdb_config["password"])
        return mwdb

    @property
    def mwdb(self) -> MWDB:
        if not hasattr(self, "_mwdb"):
            setattr(self, "_mwdb", self._get_mwdb())
        return getattr(self, "_mwdb")

    def _add_tags(self, mwdb_object: MWDBObject, tags: List[str]):
        # Upload tags and attributes via subsequent requests
        for tag in tags:
            if tag not in mwdb_object.tags:
                self.log.info(
                    "[%s %s] Adding tag %s", mwdb_object.TYPE, mwdb_object.id, tag
                )
                mwdb_object.add_tag(tag)

    def _add_attributes(
        self, mwdb_object: MWDBObject, attributes: Dict[str, List[Any]]
    ):
        # Add attributes
        for key, values in attributes.items():
            for value in values:
                self.log.info(
                    "[%s %s] Adding attribute %s: %s",
                    mwdb_object.TYPE,
                    mwdb_object.id,
                    key,
                    value,
                )
                mwdb_object.add_attribute(key, value)

    def _add_comments(self, mwdb_object: MWDBObject, comments: List[str]):
        # Add comments
        for comment in comments:
            if comment not in mwdb_object.comments:
                self.log.info(
                    "[%s %s] Adding comment: %s",
                    mwdb_object.TYPE,
                    mwdb_object.id,
                    repr(comment),
                )
                mwdb_object.add_comment(comment)

    def _add_parent(self, mwdb_object: MWDBObject, parent: Optional[MWDBObject]):
        if parent and all(attached.id != parent.id for attached in mwdb_object.parents):
            self.log.info(
                "[%s %s] Adding parent: %s", mwdb_object.TYPE, mwdb_object.id, parent.id
            )
            parent.add_child(parent)

    def _upload_object(
        self,
        object_getter: Optional[Callable[[], Optional[MWDBObject]]],
        object_uploader: Callable,
        object_params: Dict[str, Any],
        parent: Optional[MWDBObject],
        tags: Optional[List[str]],
        attributes: Optional[Dict[str, List[Any]]],
        comments: Optional[List[str]],
        karton_id: str,
    ) -> Tuple[bool, MWDBObject]:
        """
        Generic object uploader that submits additional metadata along with the object.
        Check MWDB Core version to submit them using the most efficient way that depends
        on currently supported API.

        :param object_getter: Object getter that returns object or None if doesn't exist
        :param object_uploader: Object uploader that uploads object to MWDB
        :param object_params: Parameters specific for object type
        :param parent: Parent object that needs to be attached to object
        :param tags: List of tags to add
        :param attributes: Set of attributes to add
        :param comments: List of comments to add
        :param karton_id: Karton root task identifier
        """
        tags = tags or []
        attributes = attributes or {}
        comments = comments or []

        if object_getter:
            existing_object = object_getter()
        else:
            existing_object = None

        if not existing_object:
            if self.mwdb.api.supports_version("2.6.0"):
                mwdb_object = object_uploader(
                    **object_params,
                    parent=parent,
                    tags=tags,
                    attributes=attributes,
                    karton_id=karton_id
                )
            else:
                # 2.0.0+ Backwards compatible version
                mwdb_object = object_uploader(
                    **object_params, parent=parent, metakeys={"karton": karton_id}
                )
                self._add_tags(mwdb_object, tags)
                self._add_attributes(mwdb_object, attributes)
        else:
            mwdb_object = existing_object
            self._add_parent(mwdb_object, parent)
            self._add_tags(mwdb_object, tags)
            self._add_attributes(mwdb_object, attributes)
        # Comments are added always
        self._add_comments(mwdb_object, comments)
        return not existing_object, mwdb_object

    def _upload_file(
        self,
        task: Task,
        resource: RemoteResource,
        parent: Optional[MWDBObject] = None,
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, List[Any]]] = None,
        comments: Optional[List[str]] = None,
    ) -> Tuple[bool, MWDBObject]:
        """
        Upload file to MWDB or get from repository if already exists
        ensuring that metadata are set
        """
        file_id = resource.sha256

        if not file_id:
            raise RuntimeError("Missing 'sha256' of file")

        # Avoid circular references (e.g. ripped from original sample)
        if parent and parent.id == file_id:
            parent = None

        def file_getter():
            return

        return self._upload_object(
            object_getter=file_getter,
            object_uploader=self.mwdb.upload_file,
            object_params=dict(name=resource.name, content=resource.content),
            parent=parent,
            tags=tags,
            attributes=attributes,
            comments=comments,
            karton_id=task.root_uid,
        )

    def _upload_config(
        self,
        task: Task,
        family: str,
        config_type: str,
        config: Dict[str, Any],
        parent: Optional[MWDBObject] = None,
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, List[Any]]] = None,
        comments: Optional[List[str]] = None,
    ) -> Tuple[bool, MWDBObject]:
        """
        Upload config to MWDB ensuring that all metadata are set.
        """
        return self._upload_object(
            object_getter=None,
            object_uploader=self.mwdb.upload_config,
            object_params=dict(
                family=family,
                cfg=config,
                config_type=config_type,
            ),
            parent=parent,
            tags=tags,
            attributes=attributes,
            comments=comments,
            karton_id=task.root_uid,
        )

    def _upload_blob(
        self,
        task,
        blob_name,
        blob_type,
        content,
        parent: Optional[MWDBObject] = None,
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, List[Any]]] = None,
        comments: Optional[List[str]] = None,
    ) -> Tuple[bool, MWDBObject]:
        """
        Upload blob to MWDB ensuring that all metadata are set.
        """
        return self._upload_object(
            object_getter=None,
            object_uploader=self.mwdb.upload_blob,
            object_params=dict(
                name=blob_name,
                type=blob_type,
                content=content,
            ),
            parent=parent,
            tags=tags,
            attributes=attributes,
            comments=comments,
            karton_id=task.root_uid,
        )

    def _tag_children_blobs(self, config: MWDBConfig) -> None:
        for item in config.config.values():
            if type(item) is MWDBBlob:
                tag = config.family
                self.log.info(
                    "[blob %s] adding family tag '%s' inherited from parent sample",
                    item.id,
                    tag,
                )
                item.add_tag(tag)

    def process_sample(self, task: Task):
        parent_payload = task.get_payload("parent")
        parent: Optional[MWDBObject]

        if isinstance(parent_payload, RemoteResource):
            # Upload parent file
            _, parent = self._upload_file(
                task,
                task.get_payload("parent"),
            )
        elif isinstance(parent_payload, str):
            # Query parent object hash
            parent = self.mwdb.query(parent_payload, raise_not_found=False)
        else:
            parent = None

        self._upload_file(
            task,
            task.get_payload("sample"),
            parent=parent,
            tags=task.get_payload("tags", []),
            attributes=task.get_payload("attributes", {}),
            comments=task.get_payload("comments", [])
            or task.get_payload("additional_info", []),
        )

    def process_config(self, task: Task):
        config_data = task.get_payload("config")
        family = (
            task.headers["family"]
            or config_data.get("family")
            or config_data.get("type", "unknown")
        )
        config_type = task.headers.get("config_type", "static")

        if "store-in-gridfs" in config_data:
            raise Exception(
                "Found a 'store-in-gridfs' item inside a config from family: %s", family
            )

        # Upload original sample
        sample: Optional[MWDBObject] = None
        if task.has_payload("sample"):
            _, sample = self._upload_file(
                task, task.get_payload("sample"), tags=["ripped:" + family]
            )

        # Upload dump that contains recognized config information
        parent: Optional[MWDBObject] = None
        if task.has_payload("parent"):
            _, parent = self._upload_file(
                task, task.get_payload("parent"), parent=sample, tags=[family]
            )

        is_new, config = self._upload_config(
            task,
            family,
            config_type,
            config_data,
            parent=parent,
            tags=task.get_payload("tags", []),
            attributes=task.get_payload("attributes", {}),
            comments=task.get_payload("comments", [])
            or task.get_payload("additional_info", []),
        )
        if not is_new:
            self._tag_children_blobs(cast(MWDBConfig, config))

    def process_blob(self, task: Task):
        parent_payload = task.get_payload("parent")
        parent: Optional[MWDBObject] = None
        if isinstance(parent_payload, RemoteResource):
            # Upload parent file
            _, parent = self._upload_file(
                task,
                task.get_payload("parent"),
            )
        elif isinstance(parent_payload, str):
            # Query parent object hash
            parent = self.mwdb.query(parent_payload, raise_not_found=False)

        self._upload_blob(
            task,
            blob_name=task.get_payload("name"),
            blob_type=task.headers["blob_type"],
            content=task.get_payload("blob"),
            parent=parent,
            tags=task.get_payload("tags", []),
            attributes=task.get_payload("attributes", {}),
            comments=task.get_payload("comments", [])
            or task.get_payload("additional_info", []),
        )

    def process(self, task: Task) -> None:  # type: ignore
        object_type = task.headers["type"]
        mwdb_object: Optional[MWDBObject]

        if object_type == "sample":
            self.process_sample(task)
        elif object_type == "config":
            self.process_config(task)
        elif object_type == "blob":
            self.process_blob(task)
        else:
            raise RuntimeError("Unsupported object type")
