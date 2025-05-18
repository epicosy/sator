from cement import Controller, ex


class Extract(Controller):
    class Meta:
        label = 'extract'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator extract'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Extracts attributes from the description of the specified vulnerability.',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability_attributes(self):
        vulnerability_attributes_extraction = self.app.extraction_builder.create_vulnerability_attributes_extraction()
        vul_attrs = vulnerability_attributes_extraction.extract_vulnerability_attributes(self.app.pargs.vulnerability_id)

        print(vul_attrs)

    @ex(
        help='Extracts attributes from the patch references of the specified vulnerability.',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def patch_attributes(self):
        patch_attributes_extraction = self.app.extraction_builder.create_patch_attributes_extraction()
        patch_attrs = patch_attributes_extraction.extract_patch_attributes(self.app.pargs.vulnerability_id)

        print(patch_attrs)
