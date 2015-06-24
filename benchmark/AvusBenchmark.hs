import Avus.Scan
import Criterion.Main

noopProcessData :: FilePath -> IO ()
noopProcessData fp = processData (Just fp) (Just "null") $
  processVuln (\_ b -> return b)  -- noop update functions
              (\_ t -> return t)
              (\_ e -> return e)

main :: IO ()
main = defaultMain [
  bgroup "noop" [
    bench "noopProcessData 20" $ nfIO (noopProcessData "benchmark/sample.csv"),
    bench "noopProcessData 200" $ nfIO (noopProcessData "benchmark/sample200.csv")
    ]
  ]
