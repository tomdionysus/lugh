#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

# Executables, tools/lugh_<tool>.cpp building lugh-<tool>. lugh-node is the service: a node
# of the cluster running Lugh.
add_executable(lugh-node lugh_node.cpp)
target_link_libraries(lugh-node PRIVATE lugh)
lugh_flags(lugh-node)
