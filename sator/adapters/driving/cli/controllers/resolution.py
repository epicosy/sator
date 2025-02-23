from cement import Controller, ex


class Resolve(Controller):
    class Meta:
        label = 'resolve'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator resolve'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Resolves the metadata for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability_metadata(self):
        metadata = self.app.vulnerability_resolution.get_metadata(self.app.pargs.vuln_id)
        print(f'Metadata: {metadata}')

    @ex(
        help='Resolves the description for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability_description(self):
        description = self.app.vulnerability_resolution.get_description(self.app.pargs.vuln_id)
        print(f'Description: {description}')

    @ex(
        help='Resolves the product references for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def product_references(self):
        product_references = self.app.product_references_resolution.search_product_references(self.app.pargs.vuln_id)

        print(product_references)

    @ex(
        help='Resolves the references for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability_references(self):
        vuln_references = self.app.vulnerability_references_resolution.search_vulnerability_references(
            self.app.pargs.vuln_id
        )

        print(vuln_references)

    @ex(
        help='Resolves the references for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def patch_references(self):
        patch_references = self.app.patch_references_resolution.search_patch_references(self.app.pargs.vuln_id)

        print(patch_references)
