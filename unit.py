#!/usr/bin/python
# Metatroller and TorCtl Unit Tests

"""
Unit tests
"""

import metatroller
import copy
import TorCtl
c = metatroller.startup()

print "Done!"

# TODO: Tests:
#  - Test each NodeRestriction and print in/out lines for it
#  - Test NodeGenerator and reapply NodeRestrictions
#  - Same for PathSelector and PathRestrictions
#    - Also Reapply each restriction by hand to path. Verify returns true

def do_unit(rst, r_list):
    print "\n"
    print rst.r_is_ok.im_class
    for r in r_list:
        print r.name+" "+r.os+" "+str(r.version)+"="+str(rst.r_is_ok(r))

# Need copy for threadsafeness (XXX: hopefully it is atomic)
sorted_r = copy.copy(metatroller.sorted_r)
pct_rst = metatroller.PercentileRestriction(10, 20, sorted_r)
oss_rst = metatroller.OSRestriction([r"[lL]inux", r"BSD", "Darwin"], [])
prop_rst = metatroller.OSRestriction([], ["Windows", "Solaris"])

#do_unit(metatroller.VersionRangeRestriction("0.1.2.0"), sorted_r)
#do_unit(metatroller.VersionRangeRestriction("0.1.2.0", "0.1.2.5"), sorted_r)
#do_unit(metatroller.VersionIncludeRestriction(["0.1.1.26-alpha"]), sorted_r)
#do_unit(metatroller.VersionExcludeRestriction(["0.1.1.26"]), sorted_r)

#do_unit(metatroller.ConserveExitsRestriction(), sorted_r)

#do_unit(metatroller.FlagsRestriction([], ["Valid"]), sorted_r)

# TODO: Cross check ns exit flag with this list
#do_unit(metatroller.ExitPolicyRestriction("255.255.255.255", 25), sorted_r)

#do_unit(pct_rst, sorted_r)
#do_unit(oss_rst, sorted_r)
#do_unit(alpha_rst, sorted_r)
    
rl =  [metatroller.ExitPolicyRestriction("255.255.255.255", 80), metatroller.OrRestriction(metatroller.ExitPolicyRestriction("255.255.255.255", 443), metatroller.ExitPolicyRestriction("255.255.255.255", 6667)), metatroller.FlagsRestriction([], ["BadExit"])]

exit_rstr = TorCtl.NodeRestrictionList(rl, sorted_r)

ug = metatroller.UniformGenerator(exit_rstr)

for r in ug.next_r():
    print "Checking: " + r.name
    for rs in rl:
        if not rs.r_is_ok(r):
            raise FuxxorateException()
