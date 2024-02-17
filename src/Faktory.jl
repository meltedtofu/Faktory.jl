module Faktory

using Sockets, Random, JSON, SHA

export
    Client,
    connect!,
    close!,
    info,
    publish,
    fetch,
    ack,
    fail

"""
A low-level client for the Faktory background job server.

The specification can be found at https://github.com/contribsys/faktory/blob/main/docs/protocol-specification.md
"""
mutable struct Client
    id::String
    socket::Union{Nothing, TCPSocket}
    heartbeat::Union{Nothing, Timer}
    lock::ReentrantLock

    Client() = new(randstring(12), nothing, nothing, ReentrantLock())
end

"""
Initialize a connection to Faktory.

This will also start a background timer to keep the connection alive with heartbeat messages.
Set oneshot=true if you want to skip the heartbeat.
"""
function connect!(c::Client, host::String, port::Integer; oneshot::Bool=false, password::Union{String, Nothing}=nothing)
    workerpayload = Dict{String, Any}("hostname" => gethostname(), "pid" => getpid(), "wid" => c.id, "v" => 2, "labels" => ["julia"])
    c.socket = connect(host, port)
    if isnothing(password)
      @assert readline(c.socket) == "+HI {\"v\":2}"
    else
      raw_payload = readline(c.socket)
      response = JSON.parse(String(SubString(raw_payload, 5)))
      data = password*get(response, "s", "")
      iterations = get(response, "i", 0)
      for _ in 1:iterations
        data = sha256(data)
      end
      workerpayload["pwdhash"] = bytes2hex(data)
    end
    hello = "HELLO $(JSON.json(workerpayload))\r\n"
    write(c.socket, hello)
    @assert readline(c.socket) == "+OK"

    if !oneshot
      beat(t) = begin
          if Base.isopen(c.socket)
              msg = "BEAT {\"wid\":\"$(c.id)\", \"rss_kb\":$(Sys.maxrss()÷1024)}\r\n"
              lock(c.lock)
              write(c.socket, msg)
              response = readline(c.socket)
              unlock(c.lock)
              @assert response == "+OK"
              #TODO parse state and terminate/quiet if necessary (assert does this the noisy way)
          else
              close!(c)
          end
      end
      c.heartbeat = Timer(beat, 0; interval=15)
    end

    nothing
end

"""
End the connection with Faktory
"""
function close!(c::Client)
    if !isnothing(c.heartbeat)
        Base.close(c.heartbeat)
        c.heartbeat = nothing
    end

    if !isnothing(c.socket)
        Base.close(c.socket)
        c.socket = nothing
    end
end

"""
publish a job and receive the jobid
"""
function publish(c::Client, jobtype::String, payload; queue::String="default", reserve_for::Int=1800)::String
    jid = randstring(18)
    msg = "PUSH {\"jid\":\"$(jid)\",\"jobtype\":\"$(jobtype)\",\"queue\":\"$(queue)\",\"reserve_for\":$(reserve_for),\"args\":[$(JSON.json(payload))]}\r\n"
    lock(c.lock)
    write(c.socket, msg)
    response = readline(c.socket)
    unlock(c.lock)
    @assert response == "+OK"
    jid
end

"""
request work from the job server, optionally selecting the desired queue
"""
function fetch(c::Client; queue::String="default")
    lock(c.lock)
    write(c.socket, "FETCH $(queue)\r\n")
    response = readline(c.socket)
    length = parse(Int, response[2:end])
    if length < 0
        unlock(c.lock)
        return nothing
    end
    raw_payload = read(c.socket, length+2)
    unlock(c.lock)
    JSON.parse(String(raw_payload))
end

"""
acknowledge the successful compeletion of a job
"""
function ack(c::Client, jid::String)
    lock(c.lock)
    write(c.socket, "ACK {\"jid\":\"$(jid)\"}\r\n")
    response = readline(c.socket)
    unlock(c.lock)
    @assert response == "+OK"
    nothing
end

"""
mark a job as failed.
"""
function fail(c::Client, jid::String; errtype::String="RuntimeError", message::String="Unspecified", backtrace::Vector{String}=Vector{String}([]))
    msg = "FAIL {\"jid\":\"$(jid)\", \"errtype\":\"$(errtype)\", \"message\":$(message), \"backtrace\":$(JSON.json(backtrace))}\r\n"
    lock(c.lock)
    write(c.socket, msg)
    resp = readline(c.socket)
    unlock(c.lock)
    @assert resp == "+OK"
    nothing
end

"""
fetch various information about the server
"""
function info(c::Client)::String
    lock(c.lock)
    write(c.socket, "INFO\r\n")
    response = readline(c.socket)
    length = parse(Int, response[2:end])
    if length < 0
        unlock(c.lock)
        return ""
    end
    raw_info = read(c.socket, length+2)
    unlock(c.lock)
    String(raw_info)
end

end # module Faktory
