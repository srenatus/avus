{-# LANGUAGE NamedFieldPuns #-}
module Rivum
    ( processScan
    , Config(..)
    , defaultConfig
    ) where

import qualified Config.Dyre as Dyre
import qualified Config.Dyre.Options as Dyre
import Config.Dyre.Relaunch

import System.FilePath
import System.Exit (exitSuccess, exitFailure)
import System.Environment (getArgs)
import qualified Rivum.CVSS as CVSS
import qualified Rivum.Scan as Scan

data Config = Config
    { baseUpdate :: FilePath -> CVSS.Base -> IO CVSS.Base
    , tempUpdate :: FilePath -> CVSS.Temp -> IO CVSS.Temp
    , envUpdate :: FilePath -> CVSS.Env -> IO CVSS.Env
    , err :: Maybe String
    }

realMain :: Config -> IO ()
realMain Config{ err = Just err } = do
    putStrLn $ "Error: " ++ err
    exitFailure

realMain Config{ baseUpdate, tempUpdate, envUpdate } = do
    [fp] <- getArgs
    Scan.processData fp $ Scan.processVuln baseUpdate tempUpdate envUpdate
    exitSuccess

showError :: Config -> String -> Config
showError c str = c { err = Just str }

defaultConfig :: Config
defaultConfig = Config
    { baseUpdate = \_ b -> return b
    , tempUpdate = \_ t -> return t
    , envUpdate  = \_ e -> return e
    , err        = Nothing
    }

processScan :: Config -> IO ()
processScan cfg = Dyre.wrapMain Dyre.defaultParams
      { Dyre.projectName = "rivum"
      , Dyre.realMain    = realMain
      , Dyre.showError   = showError
      } cfg
