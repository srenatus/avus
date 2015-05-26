{-# LANGUAGE NamedFieldPuns #-}
module Rivum
    ( Config(..)
    , processScan
    , defaultConfig
    ) where

import qualified Config.Dyre as Dyre
import qualified Config.Dyre.Options as Dyre
import Config.Dyre.Relaunch
import Data.Maybe (fromMaybe)

import System.FilePath
import System.Exit (exitSuccess, exitFailure)
import System.Environment (getArgs)
import System.Console.GetOpt
import qualified Rivum.CVSS as CVSS
import qualified Rivum.Scan as Scan

-- | Config data type
--   Includes update functions for the CVSS configurations and an error value,
--   that is used to relay dyre errors (and should not be user-defined).
data Config = Config
    { baseUpdate :: FilePath -> CVSS.Base -> IO CVSS.Base  -- ^ base
    , tempUpdate :: FilePath -> CVSS.Temp -> IO CVSS.Temp  -- ^ temp
    , envUpdate :: FilePath -> CVSS.Env -> IO CVSS.Env     -- ^ env
    , err :: Maybe String                                  -- ^ optional error
    }

data Flag = Version | Output (Maybe String) deriving Show

opts :: [OptDescr Flag]
opts =
    [ Option ['V'] ["version"] (NoArg Version)      "show version (TODO)"
    , Option ['o'] ["out"]     (OptArg Output "FILE") "output to FILE (defaults to stdout)"
    ]

getOpts :: [String] -> IO ([Flag], [String])
getOpts argv = case getOpt Permute opts argv of
    (o, r, [])   -> return (o, r)
    (_, _, errs) -> ioError (userError (concat errs ++ usageInfo header opts))
  where
    header = "Usage: rivum [OPTION...] [FILE]"

findOutput :: [Flag] -> Maybe String
findOutput ((Output x):_) = x
findOutput (_:xs)         = findOutput xs
findOutput []             = Nothing

-- Dyre passed an error, print it and exit 1
realMain :: Config -> IO ()
realMain Config{ err = Just err } = do
    putStrLn $ "Error: " ++ err
    exitFailure

-- TODO: handle version
realMain Config{ baseUpdate, tempUpdate, envUpdate } = do
    (flags, fs) <- getOpts =<< getArgs

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
    , err        = Nothing
    }

-- | Quasi-main function that is used to run rivum in a user-specified way
--   See `examples/rivum.hs`.
processScan :: Config -> IO ()
processScan = Dyre.wrapMain Dyre.defaultParams
      { Dyre.projectName = "rivum"
      , Dyre.realMain    = realMain
      , Dyre.showError   = showError
      }
