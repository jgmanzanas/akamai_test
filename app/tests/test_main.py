import base64
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.exceptions import HTTPException

from app.main import app
from app.utils import AuthenticationHelper, PasswordHelper
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
@patch.object(
    HTTPBasic, '__call__',
    return_value=HTTPBasicCredentials(username='test_user', password='test_password')
)
def test_issue_token(
    mock_check_user_authentication, mock_generate_user_token, mock_authentication
) -> None:
    authorization = base64.b64encode(b'user:pass')
    headers = {'Authorization': authorization}
    response = client.get("/issue-token", headers=headers)
    assert response.status_code == 200
    assert response.json() == {'access_token': 'user-token'}


@patch.object(
    AuthenticationHelper, 'check_user_authentication',
    side_effect=HTTPException(status_code=404, detail='User not found')
)
@patch.object(
    HTTPBasic, '__call__',
    return_value=HTTPBasicCredentials(username='test_user', password='test_password')
)
def test_issue_token_user_not_found(
    mock_check_user_authentication, mock_authentication
) -> None:
    authorization = base64.b64encode(b'invalid_user:invalid_pass')
    headers = {'Authorization': authorization}
    response = client.get("/issue-token", headers=headers)
    assert response.status_code == 404
    assert response.json() == {'detail': 'User not found'}


@patch.object(
    AuthenticationHelper, 'check_user_authentication',
    side_effect=HTTPException(status_code=403, detail='Invalid authentication')
)
@patch.object(
    HTTPBasic, '__call__',
    return_value=HTTPBasicCredentials(username='test_user', password='test_password')
)
def test_issue_token_user_invalid_password(
    mock_check_user_authentication, mock_authentication
) -> None:
    authorization = base64.b64encode(b'valid_user:invalid_pass')
    headers = {'Authorization': authorization}
    response = client.get("/issue-token", headers=headers)
    assert response.status_code == 403
    assert response.json() == {'detail': 'Invalid authentication'}
