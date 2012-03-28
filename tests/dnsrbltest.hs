import Test.HUnit
import Network.DNSRBL
import List (sort)

test1 = TestCase(do
                  x <- (sanequery "pigscanfly.ca")
                  (assertEqual "pigscanflycashouldbeclean" 
                                   [("CBL",True),("INTERSERVE",False),("NJBL",False),("PBLI",False),("PBLS",False),("SBL",False)] 
                                   (sort x) ))
tests = TestList [TestLabel "firsttest" test1]

main = runTestTT tests
