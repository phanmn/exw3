defmodule ExW3.Contract.State do
  def init() do
    table_name()
    |> :ets.new([:set, :public, :named_table])

    :ok
  end

  def put(key, value, type \\ nil) do
    table_name()
    |> :ets.insert({
      key |> table_key(type),
      value
    })
  end

  def get(key, type \\ nil) do
    table_name()
    |> :ets.lookup(key |> table_key(type))
    |> List.first()
    |> case do
      nil -> nil
      record -> record |> elem(1)
    end
  end

  def delete(key, type \\ nil) do
    table_name()
    |> :ets.delete(key |> table_key(type))
  end

  defp table_name() do
    # :exw3_state
    __MODULE__
  end

  defp table_key(key, nil) do
    key
  end

  defp table_key(key, type) do
    {type, key}
  end
end
