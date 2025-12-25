"""Unit tests for JSON helper - NO MOCKS."""

import json
from decimal import Decimal

import pytest
from shared.json_helper import DecimalEncoder, dumps


class TestDecimalEncoder:
    """Test DecimalEncoder class."""

    def test_encode_decimal_integer(self):
        """Should convert Decimal integers to int."""
        data = {"count": Decimal("42")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["count"] == 42
        assert isinstance(parsed["count"], int)

    def test_encode_decimal_float(self):
        """Should convert Decimal floats to float."""
        data = {"price": Decimal("19.99")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["price"] == 19.99
        assert isinstance(parsed["price"], float)

    def test_encode_decimal_zero(self):
        """Should handle Decimal zero."""
        data = {"value": Decimal("0")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["value"] == 0
        assert isinstance(parsed["value"], int)

    def test_encode_decimal_negative(self):
        """Should handle negative Decimals."""
        data = {"balance": Decimal("-50.25")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["balance"] == -50.25

    def test_encode_decimal_large_number(self):
        """Should handle large Decimal numbers."""
        data = {"big": Decimal("999999999999")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["big"] == 999999999999

    def test_encode_decimal_precision(self):
        """Should preserve decimal precision."""
        data = {"precise": Decimal("3.14159265359")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["precise"] == pytest.approx(3.14159265359)

    def test_encode_nested_decimals(self):
        """Should handle Decimals in nested structures."""
        data = {
            "items": [
                {"id": 1, "price": Decimal("10.50")},
                {"id": 2, "price": Decimal("20.00")},
            ]
        }
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["items"][0]["price"] == 10.50
        assert parsed["items"][1]["price"] == 20.0  # .00 becomes int

    def test_encode_mixed_types(self):
        """Should handle mix of Decimal and regular types."""
        data = {
            "string": "text",
            "int": 42,
            "float": 3.14,
            "decimal": Decimal("99.99"),
            "bool": True,
            "null": None,
        }
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["string"] == "text"
        assert parsed["int"] == 42
        assert parsed["float"] == 3.14
        assert parsed["decimal"] == 99.99
        assert parsed["bool"] is True
        assert parsed["null"] is None

    def test_encode_decimal_with_trailing_zeros(self):
        """Should convert Decimal with trailing zeros to int."""
        # Decimal("100.00") should become int 100, not float 100.0
        data = {"amount": Decimal("100.00")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["amount"] == 100
        assert isinstance(parsed["amount"], int)

    def test_encode_decimal_one_decimal_place(self):
        """Should handle Decimals with one decimal place."""
        data = {"value": Decimal("5.5")}
        result = json.dumps(data, cls=DecimalEncoder)

        parsed = json.loads(result)
        assert parsed["value"] == 5.5
        assert isinstance(parsed["value"], float)


class TestDumpsFunction:
    """Test dumps() convenience function."""

    def test_dumps_with_decimal(self):
        """Should serialize Decimal using dumps()."""
        data = {"count": Decimal("42")}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["count"] == 42

    def test_dumps_with_regular_data(self):
        """Should serialize regular data."""
        data = {"message": "hello", "value": 123}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed == data

    def test_dumps_returns_string(self):
        """Should return JSON string."""
        result = dumps({"test": "data"})
        assert isinstance(result, str)

    def test_dumps_empty_dict(self):
        """Should handle empty dict."""
        result = dumps({})
        assert result == "{}"

    def test_dumps_with_list(self):
        """Should serialize lists."""
        data = {"items": [1, 2, 3]}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["items"] == [1, 2, 3]

    def test_dumps_unicode(self):
        """Should handle Unicode characters."""
        data = {"message": "Hello 世界"}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["message"] == "Hello 世界"


class TestDynamoDBUseCase:
    """Test realistic DynamoDB use cases."""

    def test_dynamodb_response_typical(self):
        """Should handle typical DynamoDB response."""
        # DynamoDB returns numbers as Decimal
        dynamo_record = {
            "file_id": "550e8400-e29b-41d4-a716-446655440000",
            "file_size": Decimal("1048576"),  # 1 MB
            "expires_at": Decimal("1704067200"),
            "downloaded": False,
            "report_count": Decimal("0"),
        }

        result = dumps(dynamo_record)
        parsed = json.loads(result)

        assert parsed["file_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert parsed["file_size"] == 1048576
        assert isinstance(parsed["file_size"], int)
        assert parsed["expires_at"] == 1704067200
        assert isinstance(parsed["expires_at"], int)
        assert parsed["downloaded"] is False
        assert parsed["report_count"] == 0

    def test_dynamodb_scan_results(self):
        """Should handle DynamoDB scan results (list of items)."""
        items = [
            {"id": "1", "count": Decimal("10")},
            {"id": "2", "count": Decimal("20")},
            {"id": "3", "count": Decimal("30")},
        ]

        result = dumps({"Items": items})
        parsed = json.loads(result)

        assert len(parsed["Items"]) == 3
        assert all(isinstance(item["count"], int) for item in parsed["Items"])

    def test_dynamodb_update_response(self):
        """Should handle DynamoDB update response with Decimals."""
        update_response = {
            "Attributes": {
                "file_id": "test-123",
                "downloaded": True,
                "report_count": Decimal("3"),
            }
        }

        result = dumps(update_response)
        parsed = json.loads(result)

        assert parsed["Attributes"]["report_count"] == 3
        assert isinstance(parsed["Attributes"]["report_count"], int)


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_very_small_decimal(self):
        """Should handle very small Decimal values."""
        data = {"tiny": Decimal("0.0000001")}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["tiny"] == pytest.approx(0.0000001)

    def test_scientific_notation_decimal(self):
        """Should handle Decimal in scientific notation."""
        data = {"science": Decimal("1.23E+10")}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["science"] == 12300000000

    def test_decimal_negative_zero(self):
        """Should handle Decimal negative zero."""
        data = {"value": Decimal("-0")}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["value"] == 0

    def test_decimal_one(self):
        """Should handle Decimal one as integer."""
        data = {"value": Decimal("1")}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["value"] == 1
        assert isinstance(parsed["value"], int)

    def test_decimal_point_five(self):
        """Should handle Decimal 0.5 as float."""
        data = {"value": Decimal("0.5")}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["value"] == 0.5
        assert isinstance(parsed["value"], float)

    def test_deeply_nested_decimals(self):
        """Should handle deeply nested Decimal values."""
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "value": Decimal("123.456")
                    }
                }
            }
        }
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["level1"]["level2"]["level3"]["value"] == pytest.approx(123.456)

    def test_list_of_decimals(self):
        """Should handle list of Decimal values."""
        data = {"values": [Decimal("1"), Decimal("2.5"), Decimal("3.0")]}
        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["values"][0] == 1  # int
        assert parsed["values"][1] == 2.5  # float
        assert parsed["values"][2] == 3  # int (3.0 -> 3)
