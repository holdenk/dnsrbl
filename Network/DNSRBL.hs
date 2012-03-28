{- |
   Module    : Network.DNSRBL
   Copyright : (c) 2008 Holden Karau
   License   : LGPL

   Maintainer  : holden@pigscanfly.ca
   Stability   : provisional
   Portability : portable
   
   Anynchronously lookup a host on multiple DSNRBLs. 
-}
module Network.DNSRBL(dorbls,dorblf,asanequery,sanequery)  where

import ADNS (HostName,HostAddress,initResolver,Resolver,InitFlag(..),queryA)
import ADNS.Endian (readWord32)
import Control.Concurrent.Chan  ( Chan, newChan, writeChan, readChan )
import Control.Monad            (   replicateM )
import Control.Concurrent       ( forkIO )
import Data.List (sort,group)
import Data.Bits
import Data.Word
import qualified Data.Map as M

-- |A 'RBL' data type contains the information about a real time blacklist.
-- The names are the names of the different black lists 
-- and are paired with the expected result
-- The server is the server which does the resolution
-- ip is true if the RBL support lookups on IP addresses (i.e. 127.0.0.1) 
-- name is true if the RBL lookups names (i.e. foo.com)
data RBL = RBL { namexp :: [HostAddress] -> [(String,Bool)],
                    server :: String }
-- |'irbls' is the list of real time black lists used
irbls :: [RBL]
irbls = [(RBL (parsefromlist [("SBL","127.0.0.2"),
             ("CBL","127.0.0.4"),
             ("NJBL","127.0.0.5"),
             ("PBLI","127.0.0.10"),
             ("PBLS","127.0.0.11")] )
                "zen.spamhaus.org"
                ),
        (RBL (parsefromlist [("INTERSERVE","127.0.0.2")] )
                            "rbl.interserver.net"
                            ),
        (RBL (parsefromlist [("KARMASPHEREBAD","127.0.0.2")]  )
                 "karmasphere.email-sender.dnsbl.karmasphere.com"),
        (RBL (parsefromlist [("AHBLOR","127.0.0.2"),
              ("AHBLOP","127.0.0.3"),
             ("AHBSPAM","127.0.0.4"),
             ("AHBPSSLB","127.0.0.5"),
             ("AHBFSPAM","127.0.0.6"),
             ("AHBSSUP","127.0.0.7"),
             ("AHBSSUPI","127.0.0.8"),
             ("AHBEUNM","127.0.0.9"),
             ("AHBSOS","127.0.0.10"),
             ("AHBRFCFAIL","127.0.0.11"),
             ("AHB5EFAIL","127.0.0.12"),
             ("AHBORFCFAIL","127.0.0.13"),
             ("AHBCDDOS","127.0.0.14"),
             ("AHBCRELAY","127.0.0.15"),
             ("AHBCSC","127.0.0.16"),
             ("AHBWORM","127.0.0.17"),
             ("AHBVIRUS","127.0.0.18"),
             ("AHBOP2","127.0.0.19"),
             ("AHBBSPAM","127.0.0.20"),
             ("AHBMISC","127.0.0.127")] ) "dnsbl.ahbl.org")]
nrbls :: [RBL]
nrbls = [(RBL (parsefromlist [("AHRHSBL","127.0.0.2")] ) "rhsbl.ahbl.org"),
        (RBL (parsefrommask [("SURBLSPAMCOP",2),
                             ("SURBLBS",4),
                             ("SURBLPH",8),
                             ("SURBLOB",16),
                             ("SURBLAB",32),
                             ("SURBLJP",64)] ) "multi.surbl.org"),
        (RBL (parsefromlist [("EXDSNBL2","127.0.0.2"),
                           ("EXDNSBL3","127.0.0.3")]) "ex.dnsbl.org")]
-- | 'parsefrommask' takes a list of Strings and masks 
--and returns a parsing function
parsefrommask :: [(String,Word)] -> [HostAddress] -> [(String,Bool)]
parsefrommask il has = (map (\x -> (fst x,(foldr (||) False (map (matchmask (snd x)) has)))) il)
-- | 'matchmask' takes a mask and a host address and returns true if it
-- matches
matchmask :: Word -> HostAddress -> Bool
matchmask mask ha = ((.&.) b4  mask) ==  mask
                    where 
                      (b1,b2,b3,b4) = readWord32 ha
-- | 'parsefromlist' takse a list of Strings and Strings
--and makes a parsing function
parsefromlist :: [(String,String)] -> [HostAddress] -> [(String,Bool)]
parsefromlist il has = (map (\x -> (fst x,(foldr (||) False (map (== (snd x)) hass)))) il)
                       where
                         hass = map toPR has
-- | 'toRR' convers a HostAddress to a string in reverse 
-- (i.e. 127.0.0.1 printed as 1.0.0.127) 
toRR :: HostAddress -> String
toRR ha = shows b4 . ('.':) .
           shows b3 . ('.':) .
           shows b2 . ('.':) .
           shows b1 $ ""
           where
             (b1,b2,b3,b4) = readWord32 ha
-- | 'toPR' converts a HostAddress to a string
toPR :: HostAddress -> String
toPR ha = shows b1 . ('.':).
          shows b2 . ('.':).
          shows b3 . ('.':).
          shows b4 $ ""
                where
                  (b1,b2,b3,b4) = readWord32 ha

--  |Wrap queryA and return the result 
-- or in the event of an error an empty list
myqueryA :: Resolver -> HostName -> IO [HostAddress]
myqueryA resolver host =  queryA resolver host >>=(\a ->  case a of
                (Just b) -> return b
                _ -> return [] )


-- |Get the lookup strings host name in all the RBLs 
-- (resolving its IP address for the IP based RBLS)
rstrs :: String -> [HostAddress] -> [(RBL,String)] 
rstrs host ips = (namerstrs host )++(concatMap iprstrs ips)

-- |Get the lookup strings for name based RBLs

namerstrs :: HostName -> [(RBL,String)]
namerstrs host =  zip nrbls (map (\rbl -> (host++"."++(server rbl) )) nrbls )

--  Get the  lookup string for the ip based RBLs
iprstrs :: HostAddress -> [(RBL,String)]
iprstrs host =  zip irbls (map (\rbl -> ((toRR host)++"."++(server rbl) )) irbls )

-- |Is match compares a HostAddress and a String and sees if they are a match
ismatch :: ([HostAddress]->[(String,Bool)]) -> [HostAddress] -> [(String, Bool)]
ismatch  func haddr = func haddr

-- |Takes and RBL and a HostAddress list and return a list of strings 
-- (where the string is the name of the RBL) & the bool is where it is listed or not
rrtsb :: RBL -> [HostAddress] -> [(String,Bool)]
rrtsb rbl res  = ismatch (namexp rbl) res

--  | dowork does the semi-heavy lifting
dowork :: Resolver -> Chan [(String,Bool)] -> (RBL, HostName) -> IO ()
dowork resolver channel query=do
  a <- (myqueryA resolver (snd query) )
  writeChan channel (rrtsb (fst query) a)

-- |'dorbls' is a friendly wrapper around 
-- dorblf which only requires a hostname
dorbls :: String -> IO [(String,Bool)]
dorbls host = initResolver [NoErrPrint, NoServerWarn] $ \resolver -> do
                hostip <- (myqueryA resolver host )
                results <- (dorblf host hostip resolver)
                return results
-- |'dorblf' returns a list of (String,Bool) where
-- the string is the RBL name and Bool is if it was found or not
-- Note: There may be multiple instances of the same string 
-- with different Bool values since one hostname may resolve to multiple IPs
-- some of which may match and some of which may not match
dorblf :: String -> [HostAddress] -> Resolver -> IO [(String,Bool)]
dorblf host ips resolver = do
                rrChannel <- newChan :: IO (Chan [(String,Bool)])
                --results <- getChanContents rrChannel
                mapM_ (\h -> forkIO (dowork resolver rrChannel h)) queries
                --wait (length queries) results 0
                --return results
                s <- replicateM (length queries) (readChan rrChannel )
                return (concat s)
                       where
                         queries = (rstrs host ips)



-- |  'sanequery' is a Wrapper of "dorbls" which has only one instance 
-- of each RBL and
-- if any of the elements were found in the RBL (name, any of the IPs)
-- it is true, otherwise it is false
sanequery :: String -> IO [(String,Bool)]
sanequery host = do
  results <- dorbls host
  return (map (\x-> ((fst (head x)),(foldl (\y z -> y || (snd z)) False x) ) )
                  (group (sort (results))) )

-- | 'asanequery' is a wrapper of dorblf which has only one instance of RBL and
-- if any of the elements were found in the RBL (name, any of the IPs)
-- if it is true otherwise it is false.
asanequery :: String -> [HostAddress] -> Resolver -> IO [(String,Bool)]
asanequery host ipl resolver = do 
  results <- dorblf host ipl resolver
  return (map (\x-> ((fst (head x)),(foldl (\y z -> y || (snd z)) False x) ) )
                  (group (sort (results))) )
