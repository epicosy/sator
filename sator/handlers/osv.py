from cement import Handler
from sator.core.interfaces import HandlersInterface
from osvutils.core.loader import OSVDataLoader


class OSVHandler(HandlersInterface, Handler):
    class Meta:
        label = 'osv'

    def __init__(self, **kw):
        super().__init__(**kw)

    def run(self, **kwargs):
        loader = OSVDataLoader()
        loader(['CRAN'])

        print(len(loader))
