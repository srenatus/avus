{-# LANGUAGE NamedFieldPuns #-}
module Avus
    ( Config(..)
    , processScan
    , defaultConfig
    ) where

import Paths_avus (version)
import qualified Avus.CVSSv2 as CVSS
import qualified Avus.Scan as Scan

import qualified Config.Dyre          as Dyre
import qualified Config.Dyre.Options  as Dyre
import           Config.Dyre.Relaunch
import           Data.Maybe (fromMaybe)
import           Data.Version (showVersion)
import           System.FilePath
import           System.Exit (exitSuccess, exitFailure)
import           System.Environment (getArgs)
import           System.Console.GetOpt

-- | Config data type
--   Includes update functions for the CVSS configurations and an error value,
--   that is used to relay dyre errors (and should not be user-defined).
data Config = Config
    { baseUpdate :: FilePath -> CVSS.Base -> IO CVSS.Base  -- ^ base
    , tempUpdate :: FilePath -> CVSS.Temp -> IO CVSS.Temp  -- ^ temp
    , envUpdate  :: FilePath -> CVSS.Env -> IO CVSS.Env    -- ^ env
    , ref        :: Maybe String                           -- ^ optional identifier
    , err        :: Maybe String                           -- ^ optional error
    }

data Flag = Version | Output (Maybe String) deriving (Eq, Show)

opts :: [OptDescr Flag]
opts =
    [ Option ['V'] ["version"] (NoArg Version)        "show version information"
    , Option ['o'] ["out"]     (OptArg Output "FILE") "output to FILE (defaults to stdout)"
    ]

getOpts :: [String] -> IO ([Flag], [String])
getOpts argv = case getOpt Permute opts argv of
    (o, r, [])   -> return (o, r)
    (_, _, errs) -> ioError (userError (concat errs ++ usageInfo header opts))
  where
    header = "Usage: avus [OPTION...] [FILE]"

findOutput :: [Flag] -> Maybe String
findOutput ((Output x):_) = x
findOutput (_:xs)         = findOutput xs
findOutput []             = Nothing

outputVersion :: Maybe String -> IO ()
outputVersion ref = putStr versionString
  where
    versionString = (showVersion version) ++ addedRef ref
    addedRef (Just r) = "/" ++ r
    addedRef Nothing    = ""

-- Dyre passed an error, print it and exit 1
realMain :: Config -> IO ()
realMain Config{ err = Just err } = do
    putStrLn $ "Error: " ++ err
    exitFailure

realMain Config{ baseUpdate, tempUpdate, envUpdate, ref } = do
    (flags, fs) <- getOpts =<< getArgs

    if Version `elem` flags
        then do outputVersion ref
                exitSuccess
        else do
            let file = if null fs then Nothing else Just $ head fs
                outfile = findOutput flags

            Scan.processData file outfile $ Scan.processVuln baseUpdate tempUpdate envUpdate
            exitSuccess

-- |
-- >>> err $ showError defaultConfig "foo"
-- Just "foo"
showError :: Config -> String -> Config
showError c str = c { err = Just str }

-- | Default config
defaultConfig :: Config
defaultConfig = Config
    { baseUpdate = \_ b -> return b
    , tempUpdate = \_ t -> return t
    , envUpdate  = \_ e -> return e
    , ref        = Nothing
    , err        = Nothing
    }

-- | Quasi-main function that is used to run avus in a user-specified way
--   See `examples/avus.hs`.
processScan :: Config -> IO ()
processScan = Dyre.wrapMain Dyre.defaultParams
      { Dyre.projectName = "avus"
      , Dyre.realMain    = realMain
      , Dyre.showError   = showError
      }
