import Test.HUnit
import Network.DNSRBL
import List (sort)

test1 = TestCase(do
                  x <- (sanequery "pigscanfly.ca")
                  (assertEqual "pigscanflycashouldbemostlyclean" [("AHB5EFAIL",False),("AHBBSPAM",False),("AHBCDDOS",False),("AHBCRELAY",False),("AHBCSC",False),("AHBEUNM",False),("AHBFSPAM",False),("AHBLOP",False),("AHBLOR",False),("AHBMISC",False),("AHBOP2",False),("AHBORFCFAIL",False),("AHBPSSLB",False),("AHBRFCFAIL",False),("AHBSOS",False),("AHBSPAM",False),("AHBSSUP",False),("AHBSSUPI",False),("AHBVIRUS",False),("AHBWORM",False),("AHRHSBL",False),("CBL",True),("EXDNSBL3",False),("EXDSNBL2",False),("INTERSERVE",False),("KARMASPHEREBAD",True),("NJBL",False),("PBLI",False),("PBLS",False),("SBL",False),("SURBLAB",False),("SURBLBS",False),("SURBLJP",False),("SURBLOB",False),("SURBLPH",False),("SURBLSPAMCOP",False)] 
                              (sort x) ))
surblt = TestCase(do
                  x <- (sanequery "test.surbl.org")
                  (assertEqual "test.surbl.org is not classy saue" 
                              [("AHRHSBL",False),("EXDNSBL3",False),("EXDSNBL2",False),("SURBLAB",True),("SURBLBS",True),("SURBLJP",True),("SURBLOB",True),("SURBLPH",True),("SURBLSPAMCOP",True)] 
                              (sort x) ))



tests = TestList [TestLabel "firsttest" test1,TestLabel "surbltest" surblt]

main = runTestTT tests
