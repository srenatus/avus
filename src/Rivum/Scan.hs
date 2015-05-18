{-# LANGUAGE ScopedTypeVariables, DeriveGeneric #-}
module Rivum.Scan
    ( processData
    , Vuln
    )where

import qualified Data.ByteString.Lazy as BL
import Prelude hiding (mapM)
import Data.Foldable (for_)
import Data.Traversable (mapM)
import Data.Csv (ToNamedRecord, FromNamedRecord, Header)
import Data.Csv.Streaming
import GHC.Generics

import qualified Rivum.CWE as CWE

data Vuln = Vuln
    { vuln_id   :: String
    , name      :: String
    , garbage   :: String
    , cwe_name  :: String
    , cwe_id    :: CWE.Id
    , severity  :: String
    , file      :: FilePath
    , path      :: FilePath
    , parameter :: String
    , line_no   :: Integer
    } deriving (Eq, Show, Generic)

instance FromNamedRecord Vuln
instance ToNamedRecord Vuln

processData :: FilePath -> (Vuln -> IO Vuln) -> IO (Records Vuln)
processData fp f = do
    csvData <- BL.readFile fp
    let (Right (_, rs)) = decodeByName csvData :: Either String (Header, Records Vuln)
    mapM f rs
    -- for_ rs $ \x ->
    --   putStrLn $ (name x) ++ " is " ++ (vuln_id x) ++ " (" ++ (file x) ++ ")"
