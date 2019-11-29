"""
    authlib.oauth2.rfc6749.resource_protector
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Accessing Protected Resources per `Section 7`_.

    .. _`Section 7`: https://tools.ietf.org/html/rfc6749#section-7
"""

from .errors import MissingAuthorizationError, UnsupportedTokenTypeError


class ResourceProtector(object):
    """资源保护器

    需要通过 register_token_validator 方法组合 token validator ，
    然后调用 validate_request 方法验证请求

    """

    def __init__(self):
        # 组合 token validators
        self._token_validators = {}

    def register_token_validator(self, validator):
        """注册Token认证器

        注册 token validator ，存放到`self._token_validators`内部字典中，
        以`validator.TOKEN_TYPE`为 key ， validator 为 value 。

        :param validator: callable(token_string, scope, request, scope_operator),
            authlib.oauth2.rfc6750.BearerTokenValidator
        """
        if validator.TOKEN_TYPE not in self._token_validators:
            self._token_validators[validator.TOKEN_TYPE] = validator

    def validate_request(self, scope, request, scope_operator='AND'):
        """

        :param scope:
        :param request: flask.request
        :param scope_operator: str, 'AND' or 'OR'

        headers:

            Authorization: Bearer <access_token>

        """
        auth = request.headers.get('Authorization')
        if not auth:
            raise MissingAuthorizationError()

        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_parts = auth.split(None, 1)
        if len(token_parts) != 2:
            raise UnsupportedTokenTypeError()

        token_type, token_string = token_parts

        # 根据 token_type 获取 token validator
        validator = self._token_validators.get(token_type.lower())
        if not validator:
            raise UnsupportedTokenTypeError()

        return validator(token_string, scope, request, scope_operator)
