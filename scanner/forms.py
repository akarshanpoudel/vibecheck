from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator


class ScanForm(forms.Form):
    target_url = forms.CharField(
        widget=forms.URLInput(attrs={
            "class":        "url-input",
            "placeholder":  "https://your-app.vercel.app",
            "autofocus":    True,
            "spellcheck":   "false",
            "autocomplete": "url",
        }),
        max_length=2000,
        label="",
    )

    def clean_target_url(self) -> str:
        url = self.cleaned_data.get("target_url", "").strip()

        # Auto-prepend scheme — lets users paste bare domains
        if url and "://" not in url:
            url = "https://" + url

        # Block localhost and common dev-only patterns early with
        # a friendly message rather than a raw validator error.
        lower = url.lower()
        if any(h in lower for h in ("localhost", "127.0.0.1", "0.0.0.0", "::1")):
            raise ValidationError(
                "Local addresses can't be scanned — enter a publicly reachable URL."
            )

        try:
            URLValidator(schemes=["http", "https"])(url)
        except ValidationError:
            raise ValidationError(
                "Enter a valid URL — for example, https://your-app.vercel.app"
            )

        return url