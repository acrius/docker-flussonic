-module(parallel_auth).

-export([request/3]).


request(Identity, Extra, Options) ->
  case verify_whitelist(Identity, Extra, Options) of
    {answer, Answer} ->
      Answer;
    undefined ->
      case verify_blacklist(Identity, Extra, Options) of
        {answer, Answer} ->
          Answer;
        undefined ->
          verify_http(Identity, Extra, Options)
      end
  end.


verify_whitelist(Identity, #{whitelist := Filename} = _Extra, _Options) ->
  verify_iplist(Identity, Filename, {answer, {ok, []}});

verify_whitelist(_Identity, _Extra, _Options) ->
  undefined.


verify_blacklist(Identity, #{blacklist := Filename} = _Extra, _Options) ->
  verify_iplist(Identity, Filename, {answer, {error, []}});

verify_blacklist(_Identity, _Extra, _Options) ->
  undefined.


verify_iplist(Identity, Filename, Positive) ->
  IP = proplists:get_value(ip, Identity),
  IPs = read_iplist(Filename),
  %% lager:info("IP=~p", [IP]),
  %% lager:info("IPs=~p", [IPs]),
  case lists:member(IP, IPs) of
    true ->
      Positive;
    false ->
      undefined
  end.


read_iplist(Filename) ->
  case file:path_open(["priv", "/etc/flussonic"], Filename, [binary,read]) of
    {error, _} ->
      lager:info("Cannot open file ~p", [Filename]),
      [];
    {ok, F, _Path} ->
      Bin = case file:pread(F, 0, 10240) of
        {ok, Bin_} -> Bin_;
        eof -> <<>>
      end,
      file:close(F),
      [Row || Row <- binary:split(Bin,<<"\n">>, [global]), size(Row) > 0]
  end.


verify_http(Identity, Extra, Options) ->
  Pid = self(),
  proc_lib:spawn(fun() ->
    Answer = parallel_request(Identity, Extra, Options),
    Pid ! {answer, Answer}
  end),
  receive
    {answer, Answer} -> Answer
  after
    15000 -> undefined
  end.


parallel_request(Identity, Extra, Options) ->
  Answer = case file:path_open(["priv", "/etc/flussonic"], "backends.txt", [binary,read]) of
    {error, _} ->
      {error, [{code,403},{message,<<"not configured backends">>}]};
    {ok, F, _Path} ->
      Bin = case file:pread(F, 0, 10240) of
        {ok, Bin_} -> Bin_;
        eof -> <<>>
      end,
      file:close(F),
      Backends = [Row || Row <- binary:split(Bin,<<"\n">>, [global]), size(Row) > 0],

      Self = self(),
      Processes = lists:map(fun(URL) ->
        Pid = proc_lib:spawn(fun() ->
          lager:md([{media,proplists:get_value(name,Identity)}]),
          Reply = auth_http_backend:verify(URL, Extra, Identity, Options),
          Self ! {reply, self(), URL, Reply}
        end),
        erlang:monitor(process, Pid),
        Pid
      end, Backends),

      wait_for_reply(Processes)
  end,
  Answer.


wait_for_reply([]) ->
  {error, [{code,403}]};

wait_for_reply(Processes) ->
  receive
    {'DOWN', _, _, Pid, _} -> 
      wait_for_reply(lists:delete(Pid, Processes));
    {reply, Pid, _URL, {ok, Ok}} ->
      Processes1 = lists:delete(Pid, Processes),
      [erlang:exit(P, shutdown) || P <- Processes1],
      {ok, Ok};
    {reply, Pid, _URL, _} ->
      wait_for_reply(lists:delete(Pid, Processes))
  end.

