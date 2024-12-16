import pytest
import requests
from unittest.mock import Mock
from client.api.communication import initiate_connection
from client.exceptions import ServerConnectionError
from crypt.exceptions import KeyExchangeError


def test_initiate_connection_success(mocker):
    # Mock the requests.post method
    mock_post = mocker.patch("requests.post")

    # Mock server response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"server_public_key": "VALID_BASE64_PUBLIC_KEY"}
    mock_post.return_value = mock_response

    # Mock generate_keys
    mock_generate_keys = mocker.patch("client.api.communication.generate_keys")
    mock_generate_keys.return_value = (Mock(), "CLIENT_PUBLIC_KEY")

    # Mock derive_shared_key
    mock_derive_shared_key = mocker.patch("client.api.communication.derive_shared_key")
    mock_derive_shared_key.return_value = b"shared_key"

    # Call the function and check the result
    shared_key = initiate_connection("http://test-server")
    assert shared_key == b"shared_key"


def test_initiate_connection_server_error(mocker):
    # Mock the requests.post method to raise a RequestException
    mocker.patch(
        "requests.post",
        side_effect=requests.exceptions.RequestException("Connection error"),
    )

    with pytest.raises(ServerConnectionError):
        initiate_connection("http://test-server")


def test_initiate_connection_missing_key(mocker):
    # Mock the requests.post method
    mock_post = mocker.patch("requests.post")

    # Mock server response without server_public_key
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_post.return_value = mock_response

    with pytest.raises(KeyExchangeError):
        initiate_connection("http://test-server")
