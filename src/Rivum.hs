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
    , envUpdate :: FilePath -> CVSS.Env -> IO CVSS.Env
    , err :: Maybe String
    }

realMain :: Config -> IO ()
realMain Config{ err = Just err } = do
    putStrLn $ "Error: " ++ err
    exitFailure

realMain Config{ baseUpdate, envUpdate } = do
    [fp] <- getArgs
    Scan.processData fp return
    exitSuccess

showError :: Config -> String -> Config
showError c str = c { err = Just str }

defaultConfig :: Config
defaultConfig = Config
    { envUpdate  = \_ e -> return e
    , baseUpdate = \_ b -> return b
    , err        = Nothing
    }

processScan :: Config -> IO ()
processScan cfg = do
    args <- Dyre.withDyreOptions Dyre.defaultParams getArgs

    Dyre.wrapMain Dyre.defaultParams
      { Dyre.projectName = "rivum"
      , Dyre.realMain    = realMain
      , Dyre.showError   = showError
      } cfg
