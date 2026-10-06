# -*- coding: utf-8 -*-
p = 'static/js/views.js'
s = open(p, encoding='utf-8').read()
s = s.replace('export async function viewOps', 'async function viewOps')
reg = '''HP.views = { viewSituation, viewLive, viewFleet, viewConfig, viewMetrics,
             viewBandit, viewAttribution, viewSummary, viewCompare, viewTrials,
             viewEvents, viewIntel, viewRequests, viewRuns, viewEntity, viewOps,
             viewEventsGroup, viewIntelGroup, viewExperimentsGroup };'''
assert reg in s
s = s.replace(reg, '', 1)
s = s.rstrip()
assert s.endswith('})();'), repr(s[-12:])
s = s[:-len('})();')] + reg + '\n})();\n'
open(p, 'w', encoding='utf-8').write(s)
print('done: export stripped, registration at end')
