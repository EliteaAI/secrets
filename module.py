#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Module """
from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401
from tools import theme


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor

    def init(self):
        """ Init module """
        log.info("Initializing module Secrets")
        self.descriptor.init_api()
        self.descriptor.init_rpcs()
        self.descriptor.init_blueprint()

        theme.register_subsection(
            "configuration", "secrets",
            "Secrets",
            title="Secrets",
            kind="slot",
            permissions={
                "permissions": ["configuration.secrets"],
                "recommended_roles": {
                    "administration": {"admin": True, "viewer": False, "editor": False},
                    "default": {"admin": True, "viewer": False, "editor": False},
                    "developer": {"admin": True, "viewer": False, "editor": False},
                }},
            prefix="secrets_",
            weight=5,
        )

        theme.register_mode_subsection(
            "administration", "configuration",
            "secrets", "Secrets",
            title="Secrets",
            kind="slot",
            permissions={
                "permissions": ["configuration.secrets"],
                "recommended_roles": {
                    "administration": {"admin": True, "viewer": False, "editor": False},
                    "default": {"admin": True, "viewer": False, "editor": False},
                    "developer": {"admin": True, "viewer": False, "editor": False},
                }},
            prefix="administration_secrets_",
            # icon_class="fas fa-server fa-fw",
            # weight=2,
        )

        self.descriptor.init_slots()

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info("De-initializing module Secrets")
