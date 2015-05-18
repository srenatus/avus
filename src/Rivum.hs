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

import System.Environment (getArgs)
import qualified Rivum.CVSS as CVSS

data Config = Config
    { baseUpdate :: FilePath -> CVSS.Base -> IO CVSS.Base
    , envUpdate :: FilePath -> CVSS.Env -> IO CVSS.Env
    , err :: Maybe String
    }

-- readScan = undefined

realMain Config{ err = Just err }        = putStrLn $ "realMain here, error: " ++ err
realMain Config{ baseUpdate, envUpdate } = putStrLn $ "realMain here, all good"

showError c str = c { err = Just str }

defaultConfig = Config
    { envUpdate  = \f e -> return e
    , baseUpdate = \f b -> return b
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
