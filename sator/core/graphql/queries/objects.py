import graphene

from graphene.types.objecttype import ObjectType

from sator.core.graphql.objects import Vulnerability, VulnerabilityModel, CWE, CWEModel, VulnerabilityCWEModel, \
    ProductType, Commit, CommitModel, Dataset, DatasetModel, Repository, RepositoryModel, Product, ProductModel


class ObjectsQuery(ObjectType):
    cwes = graphene.List(lambda: CWE, id=graphene.ID(), exists=graphene.Boolean())
    vulnerability = graphene.Field(lambda: Vulnerability, id=graphene.ID())
    vulnerabilities = graphene.List(lambda: Vulnerability, id=graphene.ID(), first=graphene.Int(), skip=graphene.Int(),
                                    last=graphene.Int())
    product_types = graphene.List(lambda: ProductType)
    commit = graphene.Field(lambda: Commit, id=graphene.ID())
    repository = graphene.Field(lambda: Repository, id=graphene.ID())
    repositories = graphene.List(Repository)
    product = graphene.Field(Product, id=graphene.ID())
    dataset = graphene.Field(lambda: Dataset, id=graphene.ID())
    datasets = graphene.List(lambda: Dataset)


    def resolve_cwes(self, info, id=None, exists: bool = False):
        query = CWE.get_query(info)

        if id:
            query = query.filter(CWEModel.id == id)

        if exists:
            # return CWEs that have vulnerabilities associated
            query = query.join(VulnerabilityCWEModel)

        return query.order_by('id').all()

    def resolve_vulnerability(self, info, id: int):
        return Vulnerability.get_query(info).filter(VulnerabilityModel.id == id).first()

    def resolve_vulnerabilities(self, info, id=None, first: int = None, skip: int = None, last: int = None, **kwargs):
        query = Vulnerability.get_query(info).order_by(VulnerabilityModel.published_date.desc())

        if id:
            return query.filter(VulnerabilityModel.id == id)
        query = query.all()

        if skip:
            query = query[skip:]

        if first:
            query = query[:first]

        elif last:
            query = query[:last]

        return query

    def resolve_product_types(self, info):
        return ProductType.get_query(info).all()

    def resolve_commit(self, info, id: str):
        return Commit.get_query(info).filter(CommitModel.id == id).first()

    def resolve_repository(self, info, id):
        return Repository.get_query(info).filter(RepositoryModel.id == id).join(CommitModel).first()

    def resolve_repositories(self, info):
        return Repository.get_query(info).all()

    def resolve_product(self, info, id):
        return Product.get_query(info).filter(ProductModel.id == id).first()

    def resolve_dataset(self, info, id):
        return Dataset.get_query(info).filter(DatasetModel.id == id).first()

    def resolve_datasets(self, info):
        return Dataset.get_query(info).all()

