from django import forms


class ScanForm(forms.Form):
    target_url = forms.URLField(
        label="Website URL",
        assume_scheme="https",
        widget=forms.URLInput(
            attrs={
                "placeholder": "https://your-vibecoded-app.vercel.app",
                "class": "url-input",
                "autofocus": True,
            }
        ),
    )
