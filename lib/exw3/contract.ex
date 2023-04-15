defmodule ExW3.Contract do
  use GenServer
  use OK.Pipe
  require Logger

  @type opts :: {:url, String.t()}

  @doc "Begins the Contract process to manage all interactions with smart contracts"
  @spec start_link(any) :: :ignore | {:error, any} | {:ok, pid}
  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, %{}, name: name())
  end

  @doc "Registers the contract with the ContractManager process. Only :abi is required field."
  @spec register(any, list) :: :ok
  def register(contract_name, contract_info) do
    contract_name
    |> ExW3.Contract.State.put(
      register_helper(contract_info),
      :contract
    )

    :ok
  end

  @doc "Unregister the contract"
  @spec unregister(any) :: :ok
  def unregister(contract_name) do
    contract_name
    |> ExW3.Contract.State.delete(:contract)

    :ok
  end

  @doc "Sets the address for the contract specified by the name argument"
  @spec at(any, binary()) :: true
  def at(contract_name, address) do
    contract_state = contract_name |> contract()
    contract_state = Keyword.put(contract_state, :address, address)

    ExW3.Contract.State.put(contract_name, contract_state, :contract)
  end

  @doc "Returns the current Contract address"
  @spec address(any) :: binary()
  def address(contract_name) do
    contract_name
    |> contract()
    |> Keyword.get(:address)
  end

  @doc "Use a Contract's method with an eth_call"
  @spec call(any(), atom(), list(), any()) :: {:ok, any()}
  def call(contract_name, method_name, args \\ [], options \\ []) do
    contract_info =
      contract_name
      |> contract()

    with {:ok, address} <- check_option(contract_info[:address], :missing_address) do
      eth_call_helper(address, contract_info[:abi], method_name, args, options)
    else
      err -> err
    end
  end

  @doc "Get logs"
  @spec get_logs(any, any, nil | maybe_improper_list | map, [{:url, binary}]) ::
          {:error, atom | binary | map} | {:ok, list}
  def get_logs(contract_name, event_name, event_data, opts \\ []) do
    %{
      address: contract_name |> address(),
      topics: contract_name |> get_topics(event_name, event_data)
    }
    |> Map.merge(event_data |> event_data_format_helper())
    |> ExW3.Rpc.get_logs(opts)
    ~>> format_logs(contract_name, event_name)
    |> OK.wrap()
  end

  @doc "Use a Contract's method with an eth_sendTransaction"
  @spec send(any, any, any, any) :: {:error, atom | binary | map} | {:ok, any}
  def send(contract_name, method_name, args, options) do
    contract_info = contract_name |> contract()

    with {:ok, address} <- check_option(contract_info[:address], :missing_address),
         {:ok, _} <- check_option(options[:from], :missing_sender),
         {:ok, _} <- check_option(options[:gas], :missing_gas) do
      eth_send_helper(
        address,
        contract_info[:abi],
        method_name |> method_name(),
        args,
        options
      )
    else
      err -> err
    end
  end

  @doc "Returns a formatted transaction receipt for the given transaction hash(id)"
  def tx_receipt(contract_name, tx_hash) do
    {:ok, receipt} = tx_hash |> ExW3.tx_receipt()
    events = contract_name |> contract() |> Map.get(:events)

    receipt["logs"]
    |> Enum.map(fn log ->
      events
      |> Map.get(log["topics"] |> Enum.at(0))
      |> case do
        nil ->
          nil

        event_attributes ->
          log
          |> ExW3.Log.format_data(event_attributes)
      end
    end)
    |> then(fn logs ->
      {receipt, logs}
    end)
    |> OK.success()
  end

  def deploy(contract_name, args) do
    contract_info = contract_name |> contract()

    with {:ok, _} <- check_option(args[:options][:from], :missing_sender),
         {:ok, _} <- check_option(args[:options][:gas], :missing_gas),
         {:ok, bin} <-
           check_option([:bin |> ExW3.Contract.State.get(), args[:bin]], :missing_binary) do
      {contract_addr, tx_hash} = deploy_helper(bin, contract_info[:abi], args)
      {:ok, contract_addr, tx_hash}
    else
      err -> err
    end
  end

  @doc "Installs a filter on the Ethereum node. This also formats the parameters, and saves relevant information to format event logs."
  def filter(contract_name, event_name, event_data \\ %{}, opts \\ []) do
    contract = contract_name |> contract()

    %{
      address: contract[:address],
      topics: contract_name |> get_topics(event_name, event_data)
    }
    |> Map.merge(
      event_data
      |> event_data_format_helper()
    )
    |> ExW3.Rpc.new_filter(opts)
    |> tap(fn filter_id ->
      filter_id
      |> ExW3.Contract.State.put(
        %{
          contract_name: contract_name,
          event_name: event_name
        },
        :filter
      )
    end)
    |> OK.success()
  end

  @doc "Using saved information related to the filter id, event logs are formatted properly"
  @spec get_filter_changes(binary, [{:url, binary}]) :: {:ok, list}
  def get_filter_changes(filter_id, opts \\ []) do
    filter_id
    |> ExW3.Rpc.get_filter_changes(opts)
    |> case do
      [] ->
        []

      logs when is_list(logs) ->
        filter = filter_id |> ExW3.Contract.State.get(:filter)

        logs
        |> format_logs(filter[:contract_name], filter[:event_name])
    end
    |> OK.success()
  end

  def init(state) do
    ExW3.Contract.State.init()

    {:ok, state}
  end

  defp name() do
    __MODULE__
  end

  defp register_helper(contract_info) do
    if contract_info[:abi] do
      contract_info ++ init_events(contract_info[:abi])
    else
      raise "ABI not provided upon initialization"
    end
  end

  defp data_signature_helper(name, fields) do
    non_indexed_types = Enum.map(fields, &Map.get(&1, "type"))
    Enum.join([name, "(", Enum.join(non_indexed_types, ","), ")"])
  end

  defp topic_types_helper([]) do
    []
  end

  defp topic_types_helper(fields) do
    fields
    |> Enum.map(fn field ->
      "(#{field["type"]})"
    end)
  end

  defp init_events(abi) do
    events =
      Enum.filter(abi, fn {_, v} ->
        v["type"] == "event"
      end)

    names_and_signature_types_map =
      Enum.map(events, fn {name, v} ->
        types = Enum.map(v["inputs"], &Map.get(&1, "type"))
        signature = Enum.join([name, "(", Enum.join(types, ","), ")"])
        encoded_event_signature = ExW3.Utils.keccak256(signature)

        indexed_fields =
          Enum.filter(v["inputs"], fn input ->
            input["indexed"]
          end)

        indexed_names =
          Enum.map(indexed_fields, fn field ->
            field["name"]
          end)

        non_indexed_fields =
          Enum.filter(v["inputs"], fn input ->
            !input["indexed"]
          end)

        non_indexed_names =
          Enum.map(non_indexed_fields, fn field ->
            field["name"]
          end)

        data_signature = data_signature_helper(name, non_indexed_fields)

        event_attributes = %{
          signature: data_signature,
          non_indexed_names: non_indexed_names,
          topic_types: topic_types_helper(indexed_fields),
          topic_names: indexed_names
        }

        {{encoded_event_signature, event_attributes}, {name, encoded_event_signature}}
      end)

    signature_types_map =
      Enum.map(names_and_signature_types_map, fn {signature_types, _} ->
        signature_types
      end)

    names_map =
      Enum.map(names_and_signature_types_map, fn {_, names} ->
        names
      end)

    [
      events: Enum.into(signature_types_map, %{}),
      event_names: Enum.into(names_map, %{})
    ]
  end

  # Options' checkers

  defp check_option(nil, error_atom), do: {:error, error_atom}
  defp check_option([], error_atom), do: {:error, error_atom}
  defp check_option([head | _tail], _atom) when head != nil, do: {:ok, head}
  defp check_option([_head | tail], atom), do: check_option(tail, atom)
  defp check_option(value, _atom), do: {:ok, value}

  def deploy_helper(bin, abi, args) do
    constructor_arg_data =
      if arguments = args[:args] do
        constructor_abi =
          Enum.find(abi, fn {_, v} ->
            v["type"] == "constructor"
          end)

        if constructor_abi do
          {_, constructor} = constructor_abi
          input_types = Enum.map(constructor["inputs"], fn x -> x["type"] end)
          types_signature = Enum.join(["(", Enum.join(input_types, ","), ")"])

          arg_count = Enum.count(arguments)
          input_types_count = Enum.count(input_types)

          if input_types_count != arg_count do
            raise "Number of provided arguments to constructor is incorrect. Was given #{arg_count} args, looking for #{input_types_count}."
          end

          bin <>
            (ExW3.Abi.encode_data(types_signature, arguments) |> Base.encode16(case: :lower))
        else
          # IO.warn("Could not find a constructor")
          bin
        end
      else
        bin
      end

    gas = ExW3.Abi.encode_option(args[:options][:gas])
    gasPrice = ExW3.Abi.encode_option(args[:options][:gas_price])

    tx = %{
      from: args[:options][:from],
      data: "0x#{constructor_arg_data}",
      gas: gas,
      gasPrice: gasPrice
    }

    {:ok, tx_hash} = ExW3.Rpc.eth_send([tx])
    {:ok, tx_receipt} = ExW3.Rpc.tx_receipt(tx_hash)

    {tx_receipt["contractAddress"], tx_hash}
  end

  def eth_call_helper(address, abi, method_name, args, opts \\ []) do
    method_name = method_name |> method_name()

    ExW3.Rpc.eth_call([
      %{
        to: address,
        data: "0x#{ExW3.Abi.encode_method_call(abi, method_name, args)}"
      },
      "latest",
      opts
    ])
    |> case do
      {:ok, data} ->
        ([:ok] ++ ExW3.Abi.decode_output(abi, method_name, data)) |> List.to_tuple()

      {:error, err} ->
        {:error, err}
    end
  end

  defp event_data_format_helper(event_data) do
    event_data
    |> param_helper(:fromBlock)
    |> param_helper(:toBlock)
    |> Map.delete(:topics)
  end

  defp get_topics(contract_name, event_name, event_data) do
    contract_info = contract_name |> ExW3.Contract.State.get(:contract)

    event_signature = contract_info[:event_names][event_name]
    topic_types = contract_info[:events][event_signature][:topic_types]
    topic_names = contract_info[:events][event_signature][:topic_names]

    filter_topics_helper(event_signature, event_data, topic_types, topic_names)
  end

  defp filter_topics_helper(event_signature, event_data, topic_types, topic_names) do
    topics =
      if is_map(event_data[:topics]) do
        Enum.map(topic_names, fn name ->
          event_data[:topics][String.to_atom(name)]
        end)
      else
        event_data[:topics]
      end

    if topics do
      formatted_topics =
        Enum.map(0..(length(topics) - 1), fn i ->
          topic = Enum.at(topics, i)

          if topic do
            if is_list(topic) do
              topic_type = Enum.at(topic_types, i)

              Enum.map(topic, fn t ->
                "0x" <> (ExW3.Abi.encode_data(topic_type, [t]) |> Base.encode16(case: :lower))
              end)
            else
              topic_type = Enum.at(topic_types, i)
              "0x" <> (ExW3.Abi.encode_data(topic_type, [topic]) |> Base.encode16(case: :lower))
            end
          else
            topic
          end
        end)

      [event_signature] ++ formatted_topics
    else
      [event_signature]
    end
  end

  defp param_helper(event_data, key) do
    if event_data[key] do
      new_param =
        if Enum.member?(["latest", "earliest", "pending", "0"], event_data[key]) do
          event_data[key]
        else
          "0x" <>
            (ExW3.Abi.encode_data("(uint256)", [event_data[key]])
             |> Base.encode16(case: :lower))
        end

      Map.put(event_data, key, new_param)
    else
      event_data
    end
  end

  defp format_logs([], _, _) do
    []
  end

  defp format_logs(logs, contract_name, event_name) do
    event_attributes =
      contract_name
      |> get_event_attributes(event_name)

    logs
    |> Enum.map(fn log ->
      [
        ExW3.Normalize.transform_to_integer(log, [
          "blockNumber",
          "logIndex",
          "transactionIndex"
        ]),
        log
        |> Map.put(
          "data",
          log
          |> ExW3.Log.format_data(event_attributes)
        )
      ]
      |> Enum.reduce(&Map.merge/2)
    end)
  end

  def get_event_attributes(contract_name, event_name) do
    contract_info = contract_name |> ExW3.Contract.State.get(:contract)
    contract_info[:events][contract_info[:event_names][event_name]]
  end

  defp contract(name) do
    name
    |> ExW3.Contract.State.get(:contract)
  end

  def eth_send_helper(address, abi, method_name, args, options) do
    encoded_options =
      ExW3.Abi.encode_options(
        options,
        [:gas, :gasPrice, :value, :nonce]
      )

    gas = ExW3.Abi.encode_option(args[:options][:gas])
    gasPrice = ExW3.Abi.encode_option(args[:options][:gas_price])

    ExW3.Rpc.eth_send([
      Map.merge(
        %{
          to: address,
          data: "0x#{ExW3.Abi.encode_method_call(abi, method_name, args)}",
          gas: gas,
          gasPrice: gasPrice
        },
        Map.merge(options, encoded_options)
      )
    ])
  end

  defp method_name(name) when is_atom(name) do
    Atom.to_string(name)
  end

  defp method_name(name) do
    name
  end
end
