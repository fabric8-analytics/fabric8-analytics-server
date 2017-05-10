from . import app
import datetime

@app.template_filter('time_ago')
def time_ago(time_in, until=None):
    """ returns string saying how long ago the time on input was

    Input is in EPOCH (seconds since epoch).
    """
    if time_in is None:
        return " - "
    if until is not None:
        now = datetime.datetime.fromtimestamp(until)
    else:
        now = datetime.datetime.now()
    diff = now - time_in
    secdiff = int(diff.total_seconds())
    if secdiff < 120:
        # less than 2 minutes
        return "1 minute"
    elif secdiff < 7200:
        # less than 2 hours
        return str(secdiff // 60) + " minutes"
    elif secdiff < 172800:
        # less than 2 days
        return str(secdiff // 3600) + " hours"
    elif secdiff < 5184000:
        # less than 2 months
        return str(secdiff // 86400) + " days"
    elif secdiff < 63072000:
        # less than 2 years
        return str(secdiff // 2592000) + " months"
    else:
        # more than 2 years
        return str(secdiff // 31536000) + " days"
