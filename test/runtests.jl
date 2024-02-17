using Faktory
using Test

@testset "Faktory" begin
    testdir = dirname(@__FILE__)

    for (root, dirs, files) in walkdir(testdir)
        tests = files |> Base.Fix1(filter, f -> endswith(f, ".jl") && f != "runtests.jl") |> collect
        if endswith(root, "test")
            # Top-Level tests
            for t in tests
                include(joinpath(root, t))
            end
        else
            # Nested Tests
            @testset "$(chop(root, head=length(testdir)+1, tail=0))" begin
                for t in tests
                    include(joinpath(root, t))
                end
            end
        end
    end
end