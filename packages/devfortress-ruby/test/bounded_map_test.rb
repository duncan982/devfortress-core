# frozen_string_literal: true

require_relative "test_helper"

class BoundedMapTest < Minitest::Test
  def test_set_and_get
    map = DevFortress::BoundedMap.new(3)
    map.set("a", 1)
    assert_equal 1, map.get("a")
  end

  def test_get_missing_key_returns_nil
    map = DevFortress::BoundedMap.new(3)
    assert_nil map.get("missing")
  end

  def test_evicts_oldest_once_at_capacity
    map = DevFortress::BoundedMap.new(2)
    map.set("a", 1)
    map.set("b", 2)
    map.set("c", 3)

    refute map.has?("a")
    assert map.has?("b")
    assert map.has?("c")
    assert_equal 2, map.size
  end

  def test_set_on_existing_key_does_not_evict
    map = DevFortress::BoundedMap.new(2)
    map.set("a", 1)
    map.set("b", 2)
    map.set("a", 99)

    assert_equal 2, map.size
    assert_equal 99, map.get("a")
  end

  def test_delete_removes_entry
    map = DevFortress::BoundedMap.new(3)
    map.set("a", 1)

    assert map.delete("a")
    refute map.has?("a")
    refute map.delete("a")
  end

  def test_clear_removes_all_entries
    map = DevFortress::BoundedMap.new(3)
    map.set("a", 1)
    map.set("b", 2)
    map.clear
    assert_equal 0, map.size
  end

  def test_each_visits_all_entries
    map = DevFortress::BoundedMap.new(3)
    map.set("a", 1)
    map.set("b", 2)

    seen = {}
    map.each { |k, v| seen[k] = v }
    assert_equal({ "a" => 1, "b" => 2 }, seen)
  end
end
