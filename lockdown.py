#!/usr/bin/env python2

from sets import Set

class RBACIdent:
  def __eq__(self, other):
    pass
  def __str__(self):
    pass

class RBACObject:
  def __init__(self, backend, ident):
    self.backend = backend
    self.ident = ident
  def __eq__(self, other):
    return self.ident == other.ident

# TODO
# The interface for RBAC backends (e.g. database, YAML file, dynamic
#   in-memory policy structure)
# provides the lowest-level interface to access-control operations.
class RBACBackend:
  #### Context methods
  # auth_ident may be the same as the context_ident for the returned
  #   RBACContext object. However, that is not guaranteed to be the case,
  #   so don't rely upon that being the case.
  def getContext(self, auth_ident, auth_token):
    pass
  # may throw an exception if the given context has expired
  def getRoles(self, context_ident):
    pass
  # if getting a context creates some mapping on the backend, this
  #   frees that space. So if, for example, getContext creates a session
  #   s.t. context_ident is the session token, cleanupContext would
  #   invalidate that session.
  # this method must behave idempotently; if called multiple times in a row
  #   with the same arguments, the program should be in the same state after
  #   call n as it was after call 1 (assuming no other methods were called
  #   in between).
  # in backends for which this functionality would not make sense, this
  #   should do nothing.
  def cleanupContext(self, context_ident):
    pass
  #### Role methods -- may throw exceptions if the given roles have changed
  def getCapabilities(self, role_ident):
    pass
  def isRoleAllowed(self, role_ident, action):
    pass
  def getParent(self, role_ident):
    pass

# TODO
class RBACContext(RBACObject):
  def __enter__(self):
    return self
  def __exit__(self, exc_type, exc_value, traceback):
    self.backend.cleanupContext(self.ident)
  def getRoles(self):
    return self.backend.getRoles(self.ident)
  # checks if any of the roles in the current context, or any of their
  #   parent roles, allow for the given action
  # this maintains a set of roles checked so that it is guaranteed not
  #   to check the same role twice. In other words, if the current context
  #   has roles:
  #     users/special/developer
  #     users/special/qa
  # this will check (in order):
  #   - developer
  #   - special
  #   - user
  #   - qa
  # and that's it.
  def isAllowed(self, action):
    for role in self.getRoles():
      cur_role = role
      while cur_role is not None and cur_role not in roles:
        if cur_role.isAllowed(action):
          return True
        roles.add(cur_role)
        cur_role = cur_role.getParent()
    return False


# TODO
class RBACRole(RBACObject):
  def getCapabilities(self):
    return self.backend.getCapabilities(self.ident)
  def isAllowed(self, action):
    return self.backend.isRoleAllowed(self.ident, action)
  def getParent(self, role):
    return self.backend.getParent(self.ident)

# TODO
class RBACAction:
  def __init__(self, backend, action_type, resource):
    pass

  

