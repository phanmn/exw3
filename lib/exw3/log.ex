defmodule ExW3.Log do
  def format_data(log, event_attributes) do
    [
      log
      |> indexed_fields(event_attributes),
      log
      |> non_indexed_fields(event_attributes)
    ]
    |> Enum.reduce(&Map.merge/2)
  end

  def non_indexed_fields(log, event_attributes) do
    event_attributes[:non_indexed_names]
    |> Enum.zip(
      ExW3.Abi.decode_event(
        log |> Map.get("data"),
        event_attributes[:signature]
      )
    )
    |> Enum.into(%{})
  end

  def indexed_fields(log, event_attributes) do
    log["topics"]
    |> case do
      [_head | tail] ->
        0..(length(tail) - 1)
        |> Enum.map(fn i ->
          event_attributes[:topic_types]
          |> Enum.at(i)
          |> ExW3.Abi.decode_data(
            tail
            |> Enum.at(i)
          )
          |> elem(0)
        end)
        |> then(fn decoded_topics ->
          Enum.zip(event_attributes[:topic_names], decoded_topics)
        end)
        |> Enum.into(%{})

      _ ->
        %{}
    end
  end
end
