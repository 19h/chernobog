-- The independently checked interposer controls C srand(). This callback only
-- attests that the selected seed reached the architecture-compilation script.
local seed = tonumber(os.getenv("CHERNOBOG_CORPUS_PROTECTOR_SEED"))
assert(seed and seed >= 0 and seed <= 4294967295 and seed == math.floor(seed), "invalid corpus seed")
function OnBeforeCompilation()
    print(string.format("CHERNOBOG_CORPUS_SEED=%u", seed))
end
