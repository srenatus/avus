{-# LANGUAGE NamedFieldPuns #-}
-- module Main where
import Rivum
import Rivum.CVSS
import Rivum.Utils (returnIO)
import System.FilePath

-- Confidentiality, Integrity, Availability
data Requirements = Requirements (Req, Req, Req)
type SecurityConcept = Domain -> Requirements

data Domain = Userland
            | Kernel
            | Misc
              deriving (Eq, Show)

classify :: FilePath -> Maybe Domain
classify fp
    | fp `elem` userland = Just Userland
    | fp `elem` misc     = Just Misc
    | fp `elem` drop     = Nothing
    | otherwise          = Just Kernel
  where
    userland = ["cat.c", "echo.c", "grep.c", "kill.c", "ln.c", "ls.c",
                "mkdir.c", "mkfs.c", "wc.c", "zombie.c", "rm.c", "printf.c"]
    misc     = ["sh.c", "init.c"]
    drop     = ["stressfs.c", "usertests.c", "forktest.c"]

concept :: SecurityConcept -- NB: this is dom_config1 for findings w/ dupes
concept Userland = Requirements (ReqL, ReqL, ReqL)
concept Misc     = Requirements (ReqL, ReqL, ReqL)
concept Kernel   = Requirements (ReqL, ReqL, ReqM)

-- ignores the filepath, sets project-level parameters
xv6base :: FilePath -> Base -> Base
xv6base _ b = b { av = AvL, ac = AcL, au = AuN }

-- uses the file classification to assign domain-based requirements
xv6env :: FilePath -> Env -> Env
xv6env fp e =
    case classify fp of
        Nothing     -> e -- identity
        Just domain -> let Requirements (cr, ir, ar) = concept domain in
            e { cr, ir, ar }

xv6Config = defaultConfig
    --{ baseUpdate = \fp b -> return $ xv6base fp b
    { baseUpdate = returnIO xv6base
    , envUpdate = returnIO xv6env
    }

main = processScan xv6Config
