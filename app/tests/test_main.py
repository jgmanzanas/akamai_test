import base64
import uuid
from typing import Literal
from unittest.mock import patch

from fastapi import status
from fastapi.testclient import TestClient
from fastapi.security import HTTPBasicCredentials
from fastapi.exceptions import HTTPException

from app.main import app, security
from app.utils import AuthenticationHelper
from app.models import User

client = TestClient(app)


@patch.object(
    AuthenticationHelper, 'check_user_authentication',
    return_value=User(id=uuid.uuid4(), name='user1', password='password')
)
@patch.object(
    AuthenticationHelper, 'generate_user_token',
    return_value='user-token'
)
def test_issue_token(
    mock_check_user_authentication, mock_generate_user_token
) -> None:
    def override_dependency() -> Literal[True]: # Mock dependencies for this test
        return HTTPBasicCredentials(username='test_user', password='test_password')
    app.dependency_overrides[security] = override_dependency

    authorization = base64.b64encode(b'user:pass')
    headers = {'Authorization': authorization}
    response = client.get("/issue-token", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'access_token': 'user-token'}
    assert mock_check_user_authentication.called == True
    assert mock_generate_user_token.called == True

    app.dependency_overrides = {} # Restore dependencies

@patch.object(
    AuthenticationHelper, 'check_user_authentication',
    side_effect=HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail='User not found'
    )
)
def test_issue_token_user_not_found(mock_check_user_authentication) -> None:
    def override_dependency() -> Literal[True]: # Mock dependencies for this test
        return HTTPBasicCredentials(username='test_user', password='test_password')
    app.dependency_overrides[security] = override_dependency

    authorization = base64.b64encode(b'invalid_user:invalid_pass')
    headers = {'Authorization': authorization}
    response = client.get("/issue-token", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {'detail': 'User not found'}
    assert mock_check_user_authentication.called == True

    app.dependency_overrides = {} # Restore dependencies

@patch.object(
    AuthenticationHelper, 'check_user_authentication',
    side_effect=HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail='Invalid authentication'
    )
)
def test_issue_token_user_invalid_password(mock_check_user_authentication) -> None:
    def override_dependency() -> Literal[True]: # Mock dependencies for this test
        return HTTPBasicCredentials(username='test_user', password='test_password')
    app.dependency_overrides[security] = override_dependency

    authorization = base64.b64encode(b'valid_user:invalid_pass')
    headers = {'Authorization': authorization}
    response = client.get("/issue-token", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {'detail': 'Invalid authentication'}
    assert mock_check_user_authentication.called == True

    app.dependency_overrides = {} # Restore dependencies

def test_validate_token() -> None:
    def override_dependency() -> Literal[True]: # Mock dependencies for this test
        return True
    app.dependency_overrides[AuthenticationHelper.validate_user_token] = override_dependency

    user_token = 'some-random-valid-user-token'
    headers = {'Authorization': f'Bearer {user_token}'}
    response = client.get("/validate-token", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'validation_check': 'success'}
    
    app.dependency_overrides = {} # Restore dependencies

def test_validate_invalid_token() -> None:    
    def override_dependency() -> HTTPException: # Mock dependencies for this test
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    app.dependency_overrides[AuthenticationHelper.validate_user_token] = override_dependency

    user_token = 'some-random-invalid-user-token'
    headers = {'Authorization': f'Bearer {user_token}'}
    response = client.get("/validate-token", headers=headers)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()['detail'] == "Could not validate credentials"

    app.dependency_overrides = {} # Restore dependencies