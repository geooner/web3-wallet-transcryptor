import pytest
import json
from unittest.mock import Mock, patch
from web3 import Web3
from transcryptor import Transcryptor

@pytest.fixture
async def transcryptor():
    """Fixture to create a Transcryptor instance with mocked Web3"""
    with patch('web3.Web3') as mock_web3:
        # Mock Web3 connection
        mock_web3.HTTPProvider.return_value = Mock()
        mock_web3.return_value.is_connected.return_value = True
        mock_web3.return_value.eth.accounts = ['0x123456789']
        mock_web3.return_value.to_hex = lambda text: '0x' + text.encode().hex()
        
        instance = Transcryptor()
        await instance.ready
        return instance

@pytest.mark.asyncio
async def test_initialization(transcryptor):
    """Test successful initialization of Transcryptor"""
    assert transcryptor.web3 is not None
    assert transcryptor.web3.is_connected()

@pytest.mark.asyncio
async def test_initialization_failure():
    """Test initialization failure when Web3 connection fails"""
    with patch('web3.Web3') as mock_web3:
        mock_web3.HTTPProvider.return_value = Mock()
        mock_web3.return_value.is_connected.return_value = False
        
        with pytest.raises(Exception) as exc_info:
            instance = Transcryptor()
            await instance.ready
        
        assert "Failed to connect to Web3 provider" in str(exc_info.value)

@pytest.mark.asyncio
async def test_get_public_key(transcryptor):
    """Test retrieving encryption public key"""
    mock_response = {'result': 'mock_public_key'}
    transcryptor.web3.provider.make_request.return_value = mock_response
    
    await transcryptor._get_public_key()
    
    assert transcryptor.encryption_public_key == 'mock_public_key'
    transcryptor.web3.provider.make_request.assert_called_once()

@pytest.mark.asyncio
async def test_get_public_key_no_accounts(transcryptor):
    """Test get_public_key failure when no accounts are available"""
    transcryptor.web3.eth.accounts = []
    
    with pytest.raises(Exception) as exc_info:
        await transcryptor._get_public_key()
    
    assert "No accounts found" in str(exc_info.value)

@pytest.mark.asyncio
async def test_encrypt_public_key(transcryptor):
    """Test encrypting data with public key"""
    test_data = {'key': 'value'}
    transcryptor.encryption_public_key = 'mock_public_key'
    
    with patch('transcryptor.EncryptUtil.encrypt') as mock_encrypt:
        mock_encrypt.return_value = {'encrypted': 'data'}
        
        result = await transcryptor.encrypt_public_key(test_data)
        
        assert result.startswith('0x')
        mock_encrypt.assert_called_once_with('mock_public_key', json.dumps(test_data))

@pytest.mark.asyncio
async def test_decrypt_private_key(transcryptor):
    """Test decrypting data with private key"""
    encrypted_data = '0x123456'
    mock_response = {'result': 'decrypted_data'}
    transcryptor.web3.provider.make_request.return_value = mock_response
    
    result = await transcryptor.decrypt_private_key(encrypted_data)
    
    assert result == 'decrypted_data'
    transcryptor.web3.provider.make_request.assert_called_once()

@pytest.mark.asyncio
async def test_decrypt_private_key_no_accounts(transcryptor):
    """Test decrypt_private_key failure when no accounts are available"""
    transcryptor.web3.eth.accounts = []
    
    with pytest.raises(Exception) as exc_info:
        await transcryptor.decrypt_private_key('0x123456')
    
    assert "No accounts found" in str(exc_info.value)

@pytest.mark.asyncio
async def test_decrypt_private_key_error_response(transcryptor):
    """Test decrypt_private_key handling of error in response"""
    mock_response = {'error': 'Decryption failed'}
    transcryptor.web3.provider.make_request.return_value = mock_response
    
    with pytest.raises(Exception) as exc_info:
        await transcryptor.decrypt_private_key('0x123456')
    
    assert "Decryption failed" in str(exc_info.value) 