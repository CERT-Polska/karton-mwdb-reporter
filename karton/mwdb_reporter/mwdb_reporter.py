import argparse
import hashlib
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from karton.core import Config, Karton, RemoteResource, Task
from mwdblib import MWDB, MWDBBlob, MWDBConfig, MWDBFile, MWDBObject, config_dhash
from mwdblib.api.options import APIClientOptions
from mwdblib.exc import ObjectTooLargeError

from .__version__ import __version__


class MWDBReporter(Karton):
    """
    Uploads analysis artifacts to MWDB.

    Expected incoming task structure for samples:
    ```
    {
        "headers": {
            "type": "sample",
            "stage": "recognized" (to be processed), "analyzed" (final artifact) or "unrecognized" (unknown file)
            "kind": all but not "raw", must have known type or be checked first by "karton.classifier"
            "platform": optional target platform
            "extension": optional file type extension
        },
        "payload": {
            "sample": Resource with sample contents
            "parent": optional, Resource with parent sample contents
                      or identifier (hash) of parent object
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
            "family": <malware family>,
            "config_type": <config type> ("static" by default)
        },
        "payload": {
            "sample": Resource with **original** sample contents
                      or identifier (hash) of object
            "parent": optional, Resource with **unpacked** sample/dump contents
                      or identifier (hash) of object
            "tags": optional, list of additional tags to be added
            "attributes": optional, dict with attributes to be added
            "comments": optional, list of comments to be added (legacy alias: "additional_info")
        }
    }
    ```

    Expected incoming task structure for blobs:
    ```
    {
        "headers": {
            "type": "blob",
            "kind": <blob type>
        },
        "payload": {
            "name": String with blob name
            "content": String with blob contents
            "parent": optional, Resource with parent sample contents
                      or identifier (hash) of parent object
            "tags": optional, list of additional tags to be added
            "attributes": optional, dict with attributes (metakeys) to be added
            "comments": optional, list of comments to be added
        }
    }
    ```
    """  # noqa

    identity = "karton.mwdb-reporter"
    version = __version__
    filters = [
        {"type": "sample", "stage": "recognized"},
        {"type": "sample", "stage": "analyzed"},
        {"type": "sample", "stage": "unrecognized"},
        {"type": "config"},
        {"type": "blob"},
    ]

    def _get_mwdb(self) -> MWDB:
        mwdb_config = self.config["mwdb"]
        mwdb = MWDB(
            api_key=mwdb_config.get("api_key"),
            api_url=mwdb_config.get("api_url", APIClientOptions.api_url),
            username=mwdb_config.get("username"),
            password=mwdb_config.get("password"),
            verify_ssl=self.config.getboolean("mwdb", "verify_ssl", True),
            retry_on_downtime=True,
            use_keyring=False,
        )
        return mwdb

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.mwdb = self._get_mwdb()

        self.report_unrecognized = self.config.getboolean(
            "mwdb-reporter", "report_unrecognized", fallback=False
        )

    def _add_tags(self, mwdb_object: MWDBObject, tags: List[str]) -> None:
        # Upload tags and attributes via subsequent requests
        for tag in tags:
            if tag not in mwdb_object.tags:
                self.log.info(
                    "[%s %s] Adding tag %s", mwdb_object.TYPE, mwdb_object.id, tag
                )
                mwdb_object.add_tag(tag)
            else:
                self.log.info(
                    "[%s %s] Already tagged as %s",
                    mwdb_object.TYPE,
                    mwdb_object.id,
                    tag,
                )

    def _add_attributes(
        self, mwdb_object: MWDBObject, attributes: Dict[str, List[Any]]
    ) -> None:
        # Add attributes
        for key, values in attributes.items():
            for value in values:
                if (
                    key not in mwdb_object.attributes
                    or value not in mwdb_object.attributes[key]
                ):
                    self.log.info(
                        "[%s %s] Adding attribute %s: %s",
                        mwdb_object.TYPE,
                        mwdb_object.id,
                        key,
                        value,
                    )
                    mwdb_object.add_attribute(key, value)
                else:
                    self.log.info(
                        "[%s %s] Already added attribute %s: %s",
                        mwdb_object.TYPE,
                        mwdb_object.id,
                        key,
                        value,
                    )

    def _add_comments(self, mwdb_object: MWDBObject, comments: List[str]) -> None:
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

    def _add_parent(
        self, mwdb_object: MWDBObject, parent: Optional[MWDBObject]
    ) -> None:
        if parent:
            if all(attached.id != parent.id for attached in mwdb_object.parents):
                self.log.info(
                    "[%s %s] Adding parent: %s",
                    mwdb_object.TYPE,
                    mwdb_object.id,
                    parent.id,
                )
                parent.add_child(mwdb_object)
            else:
                self.log.info(
                    "[%s %s] Parent already added: %s",
                    mwdb_object.TYPE,
                    mwdb_object.id,
                    parent.id,
                )

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
        :return: Tuple (is new, uploaded object)
        """
        tags = tags or []
        attributes = attributes or {}
        comments = comments or []

        if object_getter:
            existing_object = object_getter()
        else:
            existing_object = None

        metadata: List[str] = []

        # Filter out 'karton' attribute which should not be reuploaded
        attributes = {k: v for k, v in attributes.items() if k != "karton"}

        if not existing_object:
            if self.mwdb.api.supports_version("2.6.0"):
                mwdb_object = object_uploader(
                    **object_params,
                    parent=parent,
                    tags=tags,
                    attributes=attributes,
                    karton_id=karton_id
                )

                if parent:
                    metadata.append("parent: " + parent.id)
                if tags:
                    metadata.append("tags: " + ",".join(tags))
                if attributes:
                    metadata.append("attributes: " + ",".join(attributes.keys()))
                if not metadata:
                    metadata_info = "no metadata"
                else:
                    metadata_info = "including " + "; ".join(metadata)
                self.log.info(
                    "[%s %s] Uploaded object %s",
                    mwdb_object.TYPE,
                    mwdb_object.id,
                    metadata_info,
                )
            else:
                # 2.0.0+ Backwards compatible version
                mwdb_object = object_uploader(
                    **object_params, parent=parent, metakeys={"karton": karton_id}
                )
                if parent:
                    metadata.append("parent: " + parent.id)
                if not metadata:
                    metadata_info = "no metadata"
                else:
                    metadata_info = "including " + "; ".join(metadata)
                self.log.info(
                    "[%s %s] Uploaded object %s",
                    mwdb_object.TYPE,
                    mwdb_object.id,
                    metadata_info,
                )
                self._add_tags(mwdb_object, tags)
                self._add_attributes(mwdb_object, attributes)
            self._add_comments(mwdb_object, comments)
        else:
            mwdb_object = existing_object
            self._add_parent(mwdb_object, parent)
            self._add_tags(mwdb_object, tags)
            self._add_attributes(mwdb_object, attributes)
            self._add_comments(mwdb_object, comments)
            self.log.info(
                "[%s %s] Added metadata to existing object",
                mwdb_object.TYPE,
                mwdb_object.id,
            )
        return not existing_object, mwdb_object

    def _upload_file(
        self,
        task: Task,
        resource: RemoteResource,
        parent: Optional[MWDBObject] = None,
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, List[Any]]] = None,
        comments: Optional[List[str]] = None,
    ) -> Optional[Tuple[bool, MWDBObject]]:
        """
        Upload file to MWDB or get from repository if already exists
        ensuring that all provided metadata are set

        :param task: Related task
        :param resource: Resource with file contents
        :param parent: Parent object that needs to be attached to object
        :param tags: List of tags to add
        :param attributes: Set of attributes to add
        :param comments: List of comments to add
        :return: Tuple (is new, uploaded object)
        """
        file_id = resource.sha256

        if not file_id:
            raise RuntimeError("Missing 'sha256' of file")

        # Avoid circular references (e.g. ripped from original sample)
        if parent and parent.id == file_id:
            parent = None

        def file_getter():
            self.log.info("[%s %s] Querying for object", MWDBFile.TYPE, file_id)
            return self.mwdb.query_file(file_id, raise_not_found=False)

        try:
            uploaded_object = self._upload_object(
                object_getter=file_getter,
                object_uploader=self.mwdb.upload_file,
                object_params=dict(name=resource.name, content=resource.content),
                parent=parent,
                tags=tags,
                attributes=attributes,
                comments=comments,
                karton_id=task.root_uid,
            )
        except ObjectTooLargeError:
            self.log.warning("[%s %s] Too large to upload", MWDBFile.TYPE, file_id)
            return None

        return uploaded_object

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
        Upload config to MWDB ensuring that all provided metadata are set.

        :param task: Related task
        :param family: Malware family
        :param config_type: Configuration type (usually 'static')
        :param config: Configuration contents
        :param parent: Parent object that needs to be attached to object
        :param tags: List of tags to add
        :param attributes: Set of attributes to add
        :param comments: List of comments to add
        :return: Tuple (is new, uploaded object)
        """
        config_id = config_dhash(config)

        def config_getter():
            self.log.info("[%s %s] Querying for object", MWDBConfig.TYPE, config_id)
            return self.mwdb.query_config(config_id, raise_not_found=False)

        return self._upload_object(
            object_getter=config_getter,
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
        Upload blob to MWDB ensuring that all provided metadata are set.

        :param task: Related task
        :param blob_name: Blob name
        :param blob_type: Blob type
        :param content: Blob content
        :param parent: Parent object that needs to be attached to object
        :param tags: List of tags to add
        :param attributes: Set of attributes to add
        :param comments: List of comments to add
        :return: Tuple (is new, uploaded object)
        """
        blob_id = hashlib.sha256(content.encode("utf-8")).hexdigest()

        def blob_getter():
            self.log.info("[%s %s] Querying for object", MWDBBlob.TYPE, blob_id)
            return self.mwdb.query_blob(blob_id, raise_not_found=False)

        return self._upload_object(
            object_getter=blob_getter,
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
        """
        Tags embedded blobs with family tag
        """
        for item in config.config.values():
            if type(item) is MWDBBlob:
                tag = config.family
                self.log.info(
                    "[%s %s] Adding family tag '%s' inherited from parent sample",
                    MWDBBlob.TYPE,
                    item.id,
                    tag,
                )
                item.add_tag(tag)

    def process_sample(self, task: Task) -> None:
        parent_payload = task.get_payload("parent")
        parent: Optional[MWDBObject]

        if task.headers.get("stage") == "unrecognized" and not self.report_unrecognized:
            self.log.info(
                (
                    "Sample is unrecognized and reporter is not configured "
                    "to report them, dropping the task"
                )
            )
            return

        if isinstance(parent_payload, RemoteResource):
            # Upload parent file
            uploaded = self._upload_file(
                task,
                task.get_payload("parent"),
            )
            if uploaded:
                _, parent = uploaded
            else:
                self.log.warning(
                    "Failed to upload parent sample, linking to root instead"
                )
                parent = None
        elif isinstance(parent_payload, str):
            # Query parent object hash
            parent = self.mwdb.query(parent_payload, raise_not_found=False)
        else:
            parent = None

        uploaded = self._upload_file(
            task,
            task.get_payload("sample"),
            parent=parent,
            tags=task.get_payload("tags", []),
            attributes=task.get_payload("attributes", {}),
            comments=task.get_payload("comments", [])
            or task.get_payload("additional_info", []),
        )
        if uploaded is None:
            self.log.warning("Failed to upload sample")

    def process_config(self, task: Task) -> None:
        config_data = task.get_payload("config")
        warning_comments = []

        family = (
            task.headers["family"]
            or config_data.get("family")
            or config_data.get("type", "unknown")
        )
        config_type = task.headers.get("config_type", "static")

        if "store-in-gridfs" in config_data:
            raise RuntimeError(
                "Found a 'store-in-gridfs' item inside a config from family: %s", family
            )

        # Upload original sample
        sample: Optional[MWDBObject] = None
        sample_payload = task.get_payload("sample")
        if isinstance(sample_payload, RemoteResource):
            # Upload original sample file
            uploaded = self._upload_file(
                task, task.get_payload("sample"), tags=["ripped:" + family]
            )
            if uploaded:
                _, sample = uploaded
            else:
                self.log.warning("Failed to upload sample for config")

        elif isinstance(sample_payload, str):
            # Query original sample object hash
            sample = self.mwdb.query_file(sample_payload, raise_not_found=False)
            if sample:
                self._add_tags(sample, ["ripped:" + family])

        # Upload dump that contains recognized config information
        parent: Optional[MWDBObject] = None
        parent_payload = task.get_payload("parent")
        if isinstance(parent_payload, RemoteResource):
            # Upload parent file
            uploaded = self._upload_file(
                task, task.get_payload("parent"), parent=sample, tags=[family]
            )
            if uploaded:
                _, parent = uploaded
            else:
                self.log.warning("Failed to upload parent for config")
                warning_comments.append(
                    "warning: mwdb-reporter failed to upload the source memory dump "
                    "and the config is linked to the closest possible relative"
                )
                # link the config to grandparent if we couldn't upload the parent
                if sample is not None:
                    parent = sample
        elif isinstance(parent_payload, str):
            # Query parent object hash
            parent = self.mwdb.query(parent_payload, raise_not_found=False)
            if parent:
                self._add_parent(parent, parent=sample)
                self._add_tags(parent, [family])

        is_new, config = self._upload_config(
            task,
            family,
            config_type,
            config_data,
            parent=parent,
            tags=task.get_payload("tags", []),
            attributes=task.get_payload("attributes", {}),
            comments=(
                task.get_payload("comments", [])
                or task.get_payload("additional_info", [])
            )
            + warning_comments,
        )
        if not is_new:
            self._tag_children_blobs(cast(MWDBConfig, config))

    def process_blob(self, task: Task) -> None:
        parent_payload = task.get_payload("parent")
        parent: Optional[MWDBObject] = None
        if isinstance(parent_payload, RemoteResource):
            # Upload parent file
            uploaded = self._upload_file(
                task,
                task.get_payload("parent"),
            )
            if uploaded is None:
                self.log.warning("Failed to upload blob parent")
                parent = None
            else:
                _, parent = uploaded
        elif isinstance(parent_payload, str):
            # Query parent object hash
            parent = self.mwdb.query(parent_payload, raise_not_found=False)

        self._upload_blob(
            task,
            blob_name=task.get_payload("name", default="blob"),
            blob_type=task.headers["kind"],
            content=task.get_payload("content"),
            parent=parent,
            tags=task.get_payload("tags", []),
            attributes=task.get_payload("attributes", {}),
            comments=task.get_payload("comments", [])
            or task.get_payload("additional_info", []),
        )

    def process(self, task: Task) -> None:
        object_type = task.headers["type"]

        if object_type == "sample":
            self.process_sample(task)
        elif object_type == "config":
            self.process_config(task)
        elif object_type == "blob":
            self.process_blob(task)
        else:
            raise RuntimeError("Unsupported object type")

    @classmethod
    def args_parser(cls) -> argparse.ArgumentParser:
        parser = super().args_parser()
        parser.add_argument(
            "--report-unrecognized",
            action="store_true",
            default=None,
            help="Upload files unrecognized by classifier (false by default)",
        )
        return parser

    @classmethod
    def config_from_args(cls, config: Config, args: argparse.Namespace) -> None:
        super().config_from_args(config, args)
        config.load_from_dict(
            {
                "mwdb-reporter": {"report_unrecognized": args.report_unrecognized},
            }
        )
