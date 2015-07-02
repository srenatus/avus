-- | Scan reading and processing module
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
module Avus.Scan
    ( processData
    , processVuln
    , Vuln(..)
    )where

import qualified Avus.CVSSv2                as CVSS
import qualified Avus.CWE                   as CWE

import qualified Data.ByteString.Lazy       as BL
import qualified Data.ByteString.Lazy.Char8 as B
import           Data.Csv                   (EncodeOptions (..),
                                             FromNamedRecord, Header,
                                             ToNamedRecord,
                                             defaultEncodeOptions,
                                             encodeByNameWith)
import           Data.Csv.Streaming
import           Data.Foldable              (for_)
import           Data.Traversable           (mapM)
import           GHC.Generics
import           Prelude                    hiding (mapM, putStr)

-- | Vulnerability data
--   processed by processData
data Vuln = Vuln
    { vuln_id   :: String        -- ^ internal id (threadfix)
    , name      :: String        -- ^ name
    , garbage   :: String        -- ^ name (again?!)
    , cwe_name  :: String        -- ^ CWE name
    , cwe_id    :: Maybe CWE.Id  -- ^ CWE id
    , severity  :: String        -- ^ severity
    , file      :: FilePath      -- ^ filename (file.c)
    , path      :: FilePath      -- ^ filepath (src/some/file.c)
    , parameter :: String        -- ^ unknown
    , line_no   :: Integer       -- ^ line number of the finding
    } deriving (Eq, Show, Generic)

instance FromNamedRecord Vuln
instance ToNamedRecord Vuln

-- | Input helper function
--   defaults to stdin
readData :: Maybe FilePath -> IO BL.ByteString
readData Nothing   = BL.getContents
readData (Just fp) = BL.readFile fp

-- | Output helper function
--   defaults to stdout
putStr :: Maybe FilePath -> BL.ByteString -> IO ()
putStr Nothing   = B.putStr
putStr (Just fp) = BL.appendFile fp

-- | Main vulnerability finding processing function.
--   given (optional) input and output files, this function will
--     1. read and decode CSV data,
--     2. apply the processVuln function
--     3. write the output record
processData :: Maybe FilePath  -- input, scan file
            -> Maybe FilePath  -- output
            -> (Vuln -> IO Vuln)
            -> IO () -- (Records Vuln)
processData fp out f = do
    csvData <- readData fp
    let (Right (hdr, rs)) = decodeByName csvData :: Either String (Header, Records Vuln)
    vs <- mapM f rs -- :: Records Vuln
    for_ vs (\x -> putStr out $ encodeByNameWith encodeOpts hdr [x])
    -- putStrLn "done"
  where
    encodeOpts = defaultEncodeOptions
        { encUseCrLf       = False
        , encIncludeHeader = False
        }

-- | Vulnerability processing function.
--   takes base, temp, and env score record update functions, and a
--   vulnerability finding, to lookup the CWE impacts, and apply the update
--   functions, to yield a vulnerability finding with an updated severity
processVuln :: (FilePath -> CVSS.Base -> IO CVSS.Base)
            -> (FilePath -> CVSS.Temp -> IO CVSS.Temp)
            -> (FilePath -> CVSS.Env -> IO CVSS.Env)
            -> Vuln
            -> IO Vuln
processVuln baseUpdate tempUpdate envUpdate (Vuln vid n g cn (Just cweId) _ filepath p pm l ) = do
    base <- baseUpdate filepath $ CWE.cweImpact cweId CVSS.defaultBase
    temp <- tempUpdate filepath CVSS.defaultTemp
    env  <- envUpdate filepath CVSS.defaultEnv
    let score = CVSS.env base temp env
        sev   = show $ CVSS.fromScore score
    return (Vuln vid n g cn (Just cweId) sev filepath p pm l)
processVuln _ _ _ v = return v
