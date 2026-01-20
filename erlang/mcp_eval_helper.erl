-module(mcp_eval_helper).
-export([eval/3]).

%% @doc Safely evaluate an Erlang expression with bindings
%% Returns: {ok, Result} | {error, {parse_error, Reason}} | {error, {eval_error, Reason}}
eval(Code, Bindings, Opts) ->
    Timeout = maps:get(timeout, Opts, 5000),
    MaxHeapSize = maps:get(max_heap_size, Opts, 10000000),

    Parent = self(),
    Ref = make_ref(),

    Pid = spawn_opt(fun() ->
        Result = try
            do_eval(Code, Bindings)
        catch
            Class:Reason:Stacktrace ->
                {error, {eval_error, {Class, Reason, Stacktrace}}}
        end,
        Parent ! {Ref, Result}
    end, [
        {max_heap_size, #{size => MaxHeapSize, kill => true, error_logger => false}},
        {priority, low}
    ]),

    receive
        {Ref, Result} ->
            Result
    after Timeout ->
        exit(Pid, kill),
        {error, {eval_error, timeout}}
    end.

do_eval(Code, Bindings) ->
    case erl_scan:string(Code) of
        {ok, Tokens, _} ->
            case erl_parse:parse_exprs(Tokens) of
                {ok, Exprs} ->
                    NonLocalHandler = fun(Name, Args) ->
                        handle_function_call(Name, Args)
                    end,

                    case erl_eval:exprs(Exprs, Bindings, {value, fun(_, _) -> error(local_function_not_allowed) end}, NonLocalHandler) of
                        {value, Value, _NewBindings} ->
                            {ok, Value};
                        Other ->
                            {error, {eval_error, {unexpected_result, Other}}}
                    end;
                {error, {_Line, _Module, ErrorInfo}} ->
                    {error, {parse_error, ErrorInfo}}
            end;
        {error, {_Line, _Module, ErrorInfo}, _} ->
            {error, {parse_error, ErrorInfo}}
    end.

%% @doc Handle non-local function calls with whitelist approach
handle_function_call({erlang, '+'}, [A, B]) when is_number(A), is_number(B) -> A + B;
handle_function_call({erlang, '-'}, [A, B]) when is_number(A), is_number(B) -> A - B;
handle_function_call({erlang, '*'}, [A, B]) when is_number(A), is_number(B) -> A * B;
handle_function_call({erlang, '/'}, [A, B]) when is_number(A), is_number(B), B =/= 0 -> A / B;
handle_function_call({erlang, 'div'}, [A, B]) when is_integer(A), is_integer(B), B =/= 0 -> A div B;
handle_function_call({erlang, 'rem'}, [A, B]) when is_integer(A), is_integer(B), B =/= 0 -> A rem B;
handle_function_call({erlang, '=='}, [A, B]) -> A == B;
handle_function_call({erlang, '/='}, [A, B]) -> A /= B;
handle_function_call({erlang, '<'}, [A, B]) -> A < B;
handle_function_call({erlang, '>'}, [A, B]) -> A > B;
handle_function_call({erlang, '=<'}, [A, B]) -> A =< B;
handle_function_call({erlang, '>='}, [A, B]) -> A >= B;
handle_function_call({erlang, '=:='}, [A, B]) -> A =:= B;
handle_function_call({erlang, '=/='}, [A, B]) -> A =/= B;
handle_function_call({erlang, 'and'}, [A, B]) when is_boolean(A), is_boolean(B) -> A and B;
handle_function_call({erlang, 'or'}, [A, B]) when is_boolean(A), is_boolean(B) -> A or B;
handle_function_call({erlang, 'xor'}, [A, B]) when is_boolean(A), is_boolean(B) -> A xor B;
handle_function_call({erlang, 'not'}, [A]) when is_boolean(A) -> not A;
handle_function_call({erlang, 'andalso'}, [A, B]) when is_boolean(A), is_boolean(B) -> A andalso B;
handle_function_call({erlang, 'orelse'}, [A, B]) when is_boolean(A), is_boolean(B) -> A orelse B;
handle_function_call({erlang, '++'}, [A, B]) when is_list(A), is_list(B) -> A ++ B;
handle_function_call({erlang, '--'}, [A, B]) when is_list(A), is_list(B) -> A -- B;
handle_function_call({erlang, 'length'}, [L]) when is_list(L) -> length(L);
handle_function_call({erlang, 'hd'}, [L]) when is_list(L), length(L) > 0 -> hd(L);
handle_function_call({erlang, 'tl'}, [L]) when is_list(L), length(L) > 0 -> tl(L);
handle_function_call({erlang, 'tuple_size'}, [T]) when is_tuple(T) -> tuple_size(T);
handle_function_call({erlang, 'element'}, [N, T]) when is_integer(N), is_tuple(T) -> element(N, T);
handle_function_call({erlang, 'is_atom'}, [T]) -> is_atom(T);
handle_function_call({erlang, 'is_binary'}, [T]) -> is_binary(T);
handle_function_call({erlang, 'is_boolean'}, [T]) -> is_boolean(T);
handle_function_call({erlang, 'is_float'}, [T]) -> is_float(T);
handle_function_call({erlang, 'is_integer'}, [T]) -> is_integer(T);
handle_function_call({erlang, 'is_list'}, [T]) -> is_list(T);
handle_function_call({erlang, 'is_map'}, [T]) -> is_map(T);
handle_function_call({erlang, 'is_number'}, [T]) -> is_number(T);
handle_function_call({erlang, 'is_pid'}, [T]) -> is_pid(T);
handle_function_call({erlang, 'is_tuple'}, [T]) -> is_tuple(T);
handle_function_call({erlang, 'map_size'}, [M]) when is_map(M) -> map_size(M);
handle_function_call({erlang, 'map_get'}, [K, M]) when is_map(M) -> map_get(K, M);
handle_function_call({erlang, 'abs'}, [N]) when is_number(N) -> abs(N);
handle_function_call({erlang, 'ceil'}, [N]) when is_number(N) -> ceil(N);
handle_function_call({erlang, 'floor'}, [N]) when is_number(N) -> floor(N);
handle_function_call({erlang, 'round'}, [N]) when is_number(N) -> round(N);
handle_function_call({erlang, 'trunc'}, [N]) when is_number(N) -> trunc(N);
handle_function_call({erlang, 'atom_to_binary'}, [A]) when is_atom(A) -> atom_to_binary(A);
handle_function_call({erlang, 'binary_to_atom'}, [B]) when is_binary(B) -> binary_to_atom(B);
handle_function_call({erlang, 'integer_to_binary'}, [I]) when is_integer(I) -> integer_to_binary(I);
handle_function_call({erlang, 'binary_to_integer'}, [B]) when is_binary(B) -> binary_to_integer(B);
handle_function_call({erlang, 'float_to_binary'}, [F]) when is_float(F) -> float_to_binary(F);
handle_function_call({erlang, 'binary_to_float'}, [B]) when is_binary(B) -> binary_to_float(B);
handle_function_call({lists, 'reverse'}, [L]) when is_list(L) -> lists:reverse(L);
handle_function_call({lists, 'sort'}, [L]) when is_list(L) -> lists:sort(L);
handle_function_call({lists, 'filter'}, [_F, _L]) -> error(function_filtering_not_allowed);
handle_function_call({lists, 'map'}, [_F, _L]) -> error(function_mapping_not_allowed);
handle_function_call({lists, 'member'}, [E, L]) when is_list(L) -> lists:member(E, L);
handle_function_call({lists, 'sum'}, [L]) when is_list(L) -> lists:sum(L);
handle_function_call({lists, 'max'}, [L]) when is_list(L), length(L) > 0 -> lists:max(L);
handle_function_call({lists, 'min'}, [L]) when is_list(L), length(L) > 0 -> lists:min(L);
handle_function_call({maps, 'keys'}, [M]) when is_map(M) -> maps:keys(M);
handle_function_call({maps, 'values'}, [M]) when is_map(M) -> maps:values(M);
handle_function_call({maps, 'to_list'}, [M]) when is_map(M) -> maps:to_list(M);
handle_function_call({maps, 'from_list'}, [L]) when is_list(L) -> maps:from_list(L);
handle_function_call({maps, 'get'}, [K, M]) when is_map(M) -> maps:get(K, M);
handle_function_call({maps, 'get'}, [K, M, Default]) when is_map(M) -> maps:get(K, M, Default);
handle_function_call({maps, 'put'}, [K, V, M]) when is_map(M) -> maps:put(K, V, M);
handle_function_call({maps, 'remove'}, [K, M]) when is_map(M) -> maps:remove(K, M);
handle_function_call({maps, 'is_key'}, [K, M]) when is_map(M) -> maps:is_key(K, M);
handle_function_call({string, 'length'}, [S]) when is_binary(S) -> string:length(S);
handle_function_call({string, 'to_upper'}, [S]) when is_binary(S) -> string:to_upper(S);
handle_function_call({string, 'to_lower'}, [S]) when is_binary(S) -> string:to_lower(S);
handle_function_call({Mod, Fun}, Args) ->
    error({forbidden_function, Mod, Fun, length(Args)}).
