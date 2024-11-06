import logging
import os

import traceback

from contextlib import contextmanager
from pydantic import BaseModel

from neutron_fwaas.temp.log import logger


class YAMLManager:
    def __init__(self, file_path: str, pydantic_class: BaseModel, yaml):
        self.file_path = file_path
        self.pydantic_class = pydantic_class
        self.yaml = yaml
        self.data = None

    def __enter__(self):
        self.load_yaml()
        return self.data

    def __exit__(self, exc_type, exc_value, exc_tb):
        if exc_type is not None:
            logger.warning(
                f"Exception '{exc_type.__name__}' occurred during YAML management: {exc_value}"
            )
            logger.warning(
                f"{''.join(traceback.format_exception(exc_type, exc_value, exc_tb))}"
            )

        if self.data == None:
            self.delete_yaml()

        self.save_yaml()
        return True  # Suppresses exception propagation

    def load_yaml(self):
        try:
            with open(self.file_path, "r") as file:
                data = self.yaml.load(file)
                self.data = self.pydantic_class.model_validate(data)
        except FileNotFoundError:
            logger.warning(f"{self.file_path} not found, creating default instance.")
            self.data = self.pydantic_class()
        except Exception as e:
            logger.warning(f"Unexpected error when reading file: {e}")
            self.data = self.pydantic_class()

    def save_yaml(self):
        try:
            with open(self.file_path, "w") as file:
                self.yaml.dump(self.data.model_dump(exclude_none=True), file)
        except Exception as e:
            raise RuntimeError(f"Error writing data to '{self.file_path}': {e}")

    def delete_yaml(self):
        """Deletes the YAML file."""
        try:
            os.remove(self.file_path)
            logger.info(f"{self.file_path} deleted successfully.")
        except FileNotFoundError:
            logger.warning(f"{self.file_path} does not exist, so cannot be deleted.")
        except Exception as e:
            logger.error(f"Error deleting file '{self.file_path}': {e}")
            raise
