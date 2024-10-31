import pytest
import disruptive  # type: ignore

from dtintegrations import data_connector, provider
import tests.events as events
from tests import framework

oidc_config_uri = ( "https://identity.dev.disruptive-technologies.com/"
                    "data-connector/.well-known/openid-configuration" 
)

class TestHttpPush():

    def test_decode_secret_invalid_type(self):
        with pytest.raises(TypeError):
            test_event = events.touch
            data_connector.HttpPush(
                headers={test_event.headers},
                body=b'',
                secret=22,
            )

    def test_decode_missing_header_token(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush(
                headers={},
                body=b'',
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )
    
    def test_decode_missing_header_org_id(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush(
                headers={},
                body=b'',
                secret='test-secret',
                oidc_config_uri=oidc_config_uri,
            )
    
    def test_decode_missing_header_oidc_config_uri(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush(
                headers={},
                body=b'',
                secret='test-secret',
                org_id='test-org-id',
            )
    def test_wrong_org_id(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush(
                headers=events.touch.headers,
                body=events.touch.body_str.encode('utf-8'),
                secret='test-secret',
                org_id='wrong-org-id',
                oidc_config_uri=oidc_config_uri,
            )


    def test_decode_expired_signature(self):
        test_event = events.touch
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush(
                headers=test_event.headers,
                body=test_event.body_str.encode('utf-8'),
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    def test_decode_checksum_mismatch(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Corrupt the body string.
        body_str = test_event.body_str + 'abc'

        # Attempt to decode the request.
        with pytest.raises(disruptive.errors.ConfigurationError):
            payload = data_connector.HttpPush(
                headers=test_event.headers,
                body=body_str.encode('utf-8'),
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    # ------------------------- Flask -------------------------
    def test_decode_flask(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.FlaskRequestFormat(test_event),
            provider=provider.FLASK,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']

    def test_decode_temperature(self, decode_mock):
        # Choose an event to receive.
        test_event = events.temperature

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.FlaskRequestFormat(test_event),
            provider=provider.FLASK,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']

    def test_decode_flask_name_casing(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        data_connector.HttpPush.from_provider(
            request=framework.FlaskRequestFormat(test_event),
            provider='fLAsk',
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

    def test_decode_flask_bad_secret(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush.from_provider(
                request=framework.FlaskRequestFormat(events.touch),
                provider=provider.FLASK,
                secret='bad-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    def test_decode_flask_bad_name(self):
        with pytest.raises(ValueError):
            data_connector.HttpPush.from_provider(
                request=framework.FlaskRequestFormat(events.touch),
                provider='Xflask',
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    # ------------------------- Django -------------------------
    def test_decode_django(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.DjangoRequestFormat(test_event),
            provider=provider.DJANGO,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']
    
    def test_decode_temperature(self, decode_mock):
        # Choose an event to receive.
        test_event = events.temperature

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.DjangoRequestFormat(test_event),
            provider=provider.DJANGO,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']

    def test_decode_django_name_casing(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        data_connector.HttpPush.from_provider(
            request=framework.DjangoRequestFormat(test_event),
            provider='djANgO',
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

    def test_decode_django_bad_secret(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush.from_provider(
                request=framework.DjangoRequestFormat(events.touch),
                provider=provider.DJANGO,
                secret='bad-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    def test_decode_django_bad_name(self):
        with pytest.raises(ValueError):
            data_connector.HttpPush.from_provider(
                request=framework.DjangoRequestFormat(events.touch),
                provider='Xdjango',
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    # ------------------------- Gcloud -------------------------
    def test_decode_gcloud(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.GcloudRequestFormat(test_event),
            provider=provider.GCLOUD,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']
    
    def test_decode_temperature(self, decode_mock):
        # Choose an event to receive.
        test_event = events.temperature

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.GcloudRequestFormat(test_event),
            provider=provider.GCLOUD,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']

    def test_decode_gcloud_name_casing(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        data_connector.HttpPush.from_provider(
            request=framework.GcloudRequestFormat(test_event),
            provider='GcLouD',
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

    def test_decode_gcloud_bad_secret(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush.from_provider(
                request=framework.GcloudRequestFormat(events.touch),
                provider=provider.GCLOUD,
                secret='bad-secret',
                oidc_config_uri=oidc_config_uri,
            )

    def test_decode_gcloud_bad_name(self):
        with pytest.raises(ValueError):
            data_connector.HttpPush.from_provider(
                request=framework.GcloudRequestFormat(events.touch),
                provider='Xgcloud',
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    # ------------------------- Lambda -------------------------
    def test_decode_lambda(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.lambda_request_format(test_event),
            provider=provider.LAMBDA,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']

    def test_decode_temperature(self, decode_mock):
        # Choose an event to receive.
        test_event = events.temperature

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.lambda_request_format(test_event),
            provider=provider.LAMBDA,
            secret='test-secret',
            org_id='test-org-id',
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']

    def test_decode_lambda_name_casing(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        data_connector.HttpPush.from_provider(
            request=framework.lambda_request_format(test_event),
            provider='lAMbdA',
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

    def test_decode_lambda_bad_secret(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush.from_provider(
                request=framework.lambda_request_format(events.touch),
                provider=provider.LAMBDA,
                secret='bad-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    def test_decode_lambda_bad_name(self):
        with pytest.raises(ValueError):
            data_connector.HttpPush.from_provider(
                request=framework.lambda_request_format(events.touch),
                provider='Xlambda',
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    # ------------------------- Azure -------------------------
    def test_decode_azure(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.AzureRequestFormat(test_event),
            provider=provider.AZURE,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']
    
    def test_decode_temperature(self, decode_mock):
        # Choose an event to receive.
        test_event = events.temperature

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        payload = data_connector.HttpPush.from_provider(
            request=framework.AzureRequestFormat(test_event),
            provider=provider.AZURE,
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

        assert isinstance(payload.event, disruptive.events.Event)
        assert payload.event.event_id == test_event.body['event']['eventId']

    def test_decode_azure_name_casing(self, decode_mock):
        # Choose an event to receive.
        test_event = events.touch

        # Update the mock event attribute.
        decode_mock.event = test_event

        # Attempt to decode the request.
        data_connector.HttpPush.from_provider(
            request=framework.AzureRequestFormat(test_event),
            provider='AzuRE',
            secret='test-secret',
            org_id='test-org-id',
            oidc_config_uri=oidc_config_uri,
        )

    def test_decode_azure_bad_secret(self):
        with pytest.raises(disruptive.errors.ConfigurationError):
            data_connector.HttpPush.from_provider(
                request=framework.AzureRequestFormat(events.touch),
                provider=provider.AZURE,
                secret='bad-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )

    def test_decode_azure_bad_name(self):
        with pytest.raises(ValueError):
            data_connector.HttpPush.from_provider(
                request=framework.AzureRequestFormat(events.touch),
                provider='Xazure',
                secret='test-secret',
                org_id='test-org-id',
                oidc_config_uri=oidc_config_uri,
            )
