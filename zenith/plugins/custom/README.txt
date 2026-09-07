# Place your custom plugins here
# Each plugin should be a .py file with a class that extends BasePlugin
#
# Example plugin:
#
#   from zenith.plugins.base_plugin import BasePlugin, PluginInfo
#
#   class MyScanner(BasePlugin):
#       INFO = PluginInfo(
#           name="My Custom Scanner",
#           version="1.0.0",
#           author="Your Name",
#           description="Scans for something specific",
#           plugin_type="scanner",
#           tags=["web"],
#       )
#
#       def run(self, target: str, **kwargs):
#           # Your logic here
#           return {"findings": []}
