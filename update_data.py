import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

c = re.sub(
    r'let users = \[\], policies = \[\], audit = \[\], secrets = \[\], rotationJobs = \[\], policyRules = \[\], serverGroups = \[\], identityUsers = \[\], authEvents = \[\], accessGroups = \[\], permissionTemplates = \[\], permissionCatalog = \[\], mfaStatus = null, providers = \[\];',
    'let users = [], policies = [], audit = [], secrets = [], rotationJobs = [], policyRules = [], serverGroups = [], identityUsers = [], authEvents = [], accessGroups = [], permissionTemplates = [], permissionCatalog = [], mfaStatus = null, providers = [], policyDefinitions = [];',
    c
)

c = re.sub(
    r'\[policies, rotationJobs, policyRules, identityUsers, authEvents\] = await Promise\.all\(\[api\("/api/policies"\), api\("/api/secret-rotation/jobs"\), api\("/api/policy-rules"\), api\("/api/identity/users"\), api\("/api/identity/auth-events"\)\]\);',
    '[policies, rotationJobs, policyRules, identityUsers, authEvents, policyDefinitions] = await Promise.all([api("/api/policies"), api("/api/secret-rotation/jobs"), api("/api/policy-rules"), api("/api/identity/users"), api("/api/identity/auth-events"), api("/api/policies/definitions")]);',
    c
)

c = re.sub(
    r'state\.data = \{ (.*?) \};',
    r'state.data = { \1, policyDefinitions };',
    c
)

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)
