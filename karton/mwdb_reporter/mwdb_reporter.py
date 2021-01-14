from typing import Any, Dict, Optional, cast

from karton.core import Karton, RemoteResource, Task
from mwdblib import MWDB, MWDBBlob, MWDBConfig, MWDBFile, MWDBObject
from mwdblib.api import API_URL

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
            "attributes": optional, dict with attributes (metakeys) to be added
            "comments": optional, list of comments to be added (legacy alias: "additional_info")
        }
    }
    ```

    Samples are decorated with tag: `kind:platform:extension` or `misc:kind` if platform is missing

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
            "attributes": optional, dict with attributes (metakeys) to be added
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
    ]
    MAX_FILE_SIZE = 1024 * 1024 * 40

    def mwdb(self) -> MWDB:
        mwdb_config = dict(self.config.config.items("mwdb"))
        mwdb = MWDB(
            api_key=mwdb_config.get("api_key"),
            api_url=mwdb_config.get("api_url", API_URL),
            retry_on_downtime=True,
        )
        if not mwdb.api.api_key:
            mwdb.login(mwdb_config["username"], mwdb_config["password"])
        return mwdb

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

    def _upload_file(
        self,
        task: Task,
        mwdb: MWDB,
        resource: RemoteResource,
        parent: Optional[MWDBObject] = None,
    ) -> Optional[MWDBFile]:
        """
        Upload file to MWDB or get from repository if already exists
        ensuring that 'karton' metakey is set.

        :param mwdb: MWDB instance
        :param resource: Karton resource containing the file contents
        :param parent: MWDBObject with sample parent
        :return: MWDBFile instance
        """
        dhash = resource.sha256

        # Avoid circular references (e.g. ripped from original sample)
        if parent and parent.id == dhash:
            parent = None

        self.log.info("[sample %s] Querying for sample", dhash)

        file = mwdb.query_file(dhash, raise_not_found=False)
        if file is not None:
            self.log.info("[sample %s] Sample already exists", dhash)

            # If file already exists: check whether parent is attached
            if parent and all(attached.id != parent.id for attached in file.parents):
                self.log.info("[sample %s] Adding parent: %s", dhash, parent.id)
                parent.add_child(file)

            # If file already exists:
            # check whether appropriate karton key exists and add it otherwise
            if task.root_uid not in file.metakeys.get("karton", []):
                self.log.info(
                    "[sample %s] Adding metakey karton: %s",
                    dhash,
                    task.root_uid,
                )
                file.add_metakey("karton", task.root_uid)
        else:
            self.log.info("[sample %s] Sample doesn't exist, uploading", dhash)

            if resource.size > MWDBReporter.MAX_FILE_SIZE:
                self.log.warn("Sample is too big (%d bytes), skipping", resource.size)
                return None

            # Consistent logging
            if parent:
                self.log.info("[sample %s] Adding parent: %s", dhash, parent.id)
            self.log.info(
                "[sample %s] Adding metakey karton: %s",
                dhash,
                task.root_uid,
            )

            file = mwdb.upload_file(
                resource.name,
                cast(bytes, resource.content),
                metakeys={"karton": task.root_uid},
                parent=parent,
            )

        return file

    def _upload_config(
        self,
        task: Task,
        mwdb: MWDB,
        family: str,
        config: Dict[str, Any],
        parent: Optional[MWDBObject] = None,
    ) -> MWDBConfig:
        """
        Upload config to MWDB ensuring that 'karton' metakey is set.

        :param mwdb: MWDB instance
        :param family: Malware family
        :param config: dict with static configuration
        :param parent: MWDBObject with config parent
        :return: MWDBFile instance
        """
        if "store-in-gridfs" in config:
            raise Exception(
                "Found a 'store-in-gridfs' item inside a config from family: %s", family
            )
        # Upload config
        config_object = mwdb.upload_config(
            family,
            config,
            parent=parent,
            metakeys={"karton": task.root_uid},
        )
        dhash = config_object.id
        self.log.info("[config %s] Uploaded %s config", dhash, family)
        if parent:
            self.log.info("[config %s] Adding parent: %s", dhash, parent.id)
        self._tag_children_blobs(config=config_object)
        self.log.info("[config %s] Adding metakey karton: %s", dhash, task.root_uid)
        return config_object

    def process_config(self, task: Task, mwdb: MWDB) -> MWDBConfig:
        """
        Processing of Config task

        Clarification:
            sample -> parent -> config
            sample is original sample
            parent is parent of the config
            config is config

        :param mwdb: MWDB instance
        :return: MWDBConfig object
        """
        config_data = task.get_payload("config")
        family = (
            task.headers["family"]
            or config_data.get("family")
            or config_data.get("type", "unknown")
        )

        if task.has_payload("sample"):
            sample = self._upload_file(task, mwdb, task.get_payload("sample"))
            if sample:
                self.log.info("[sample %s] Adding tag ripped:%s", sample.id, family)
                sample.add_tag("ripped:" + family)
            else:
                self.log.warning("Couldn't upload original sample")
        else:
            sample = None

        if task.has_payload("parent"):
            parent = self._upload_file(
                task, mwdb, task.get_payload("parent"), parent=sample
            )
            if parent:
                self.log.info("[sample %s] Adding tag %s", parent.id, family)
                parent.add_tag(family)
            else:
                self.log.warning("Couldn't upload parent sample")
        else:
            parent = None

        config = self._upload_config(task, mwdb, family, config_data, parent=parent)
        return config

    def process_sample(self, task: Task, mwdb: MWDB) -> Optional[MWDBFile]:
        """
        Processing of Sample task

        :param mwdb: MWDB instance
        :return: MWDBFile object or None
        """
        if task.has_payload("parent"):
            parent = self._upload_file(task, mwdb, task.get_payload("parent"))
        else:
            parent = None

        if task.has_payload("sample"):
            sample = self._upload_file(
                task, mwdb, task.get_payload("sample"), parent=parent
            )
        else:
            sample = None

        return sample

    def process(self, task: Task) -> None:  # type: ignore
        mwdb = self.mwdb()
        object_type = task.headers["type"]
        mwdb_object: Optional[MWDBObject]

        if object_type == "sample":
            mwdb_object = self.process_sample(task, mwdb)
        else:
            mwdb_object = self.process_config(task, mwdb)

        if not mwdb_object:
            return

        # Add payload tags
        if task.has_payload("tags"):
            for tag in task.get_payload("tags"):
                if tag not in mwdb_object.tags:
                    self.log.info(
                        "[%s %s] Adding tag %s", object_type, mwdb_object.id, tag
                    )
                    mwdb_object.add_tag(tag)

        # Add payload attributes
        if task.has_payload("attributes"):
            for key, values in task.get_payload("attributes").items():
                for value in values:
                    if value not in mwdb_object.metakeys.get(key, []):
                        self.log.info(
                            "[%s %s] Adding metakey %s: %s",
                            object_type,
                            mwdb_object.id,
                            key,
                            value,
                        )
                        mwdb_object.add_metakey(key, value)

        # Add payload comments
        comments = task.get_payload("comments") or task.get_payload("additional_info")
        if comments:
            for comment in comments:
                self.log.info(
                    "[%s %s] Adding comment: %s",
                    object_type,
                    mwdb_object.id,
                    repr(comment),
                )
                mwdb_object.add_comment(comment)
