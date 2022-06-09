import base64
from uuid import UUID
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging

class BloodHoundSchema(object):

	def __init__(self, object):
		self.Name = None
		self.SchemaIdGuid = None

		if 'name' in object.keys() and 'schemaidguid' in object.keys():
			self.Name = object.get('name').lower()
			try:
				self.SchemaIdGuid = str(UUID(bytes_le=base64.b64decode(object.get('schemaidguid')))).lower()
				logging.debug(f"Reading Schema object {ColorScheme.schema}{self.Name}[/]", extra=OBJ_EXTRA_FMT)
			except:
				logging.warning(f"Error base64 decoding SchemaIDGUID attribute on Schema {ColorScheme.schema}{self.Name}[/]", extra=OBJ_EXTRA_FMT)
