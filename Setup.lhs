#!/usr/bin/env runhaskell
>import Distribution.Simple
>import Distribution.Simple
>import Distribution.PackageDescription(PackageDescription,dataFiles)
>import Distribution.Simple.LocalBuildInfo(LocalBuildInfo)
>import System.Cmd(system)
>import Distribution.Simple.LocalBuildInfo
>import System.IO(FilePath)

>main :: IO ()
>main = defaultMainWithHooks (simpleUserHooks {runTests = runzeTests})

>runzeTests:: Args -> Bool -> PackageDescription -> LocalBuildInfo -> IO ()
>runzeTests a b pd lb = system ( "runhaskell  ./tests/dnsrbltest.hs") >> return()

