import graphene
import sqlalchemy

from graphene_sqlalchemy import SQLAlchemyObjectType

from sator.core.models import CWE as CWEModel, Abstraction as AbstractionModel, Operation as OperationModel, \
    Phase as PhaseModel, BFClass as BFClassModel, CWEOperation as CWEOperationModel, CWEPhase as CWEPhaseModel, \
    CWEBFClass as CWEBFClassModel, Vulnerability as VulnerabilityModel, VulnerabilityCWE as VulnerabilityCWEModel, \
    Reference as ReferenceModel, Commit as CommitModel, ReferenceTag as ReferenceTagModel, Tag as TagModel, \
    Repository as RepositoryModel, Configuration as ConfigurationModel, Vendor as VendorModel, Product as ProductModel,\
    CommitFile as CommitFileModel, ProductType as ProductTypeModel, RepositoryTopic as RepositoryTopicModel, \
    Topic as TopicModel, ConfigurationVulnerability as ConfigurationVulnerabilityModel, Grouping as GroupingModel, \
    Dataset as DatasetModel, DatasetVulnerability as DatasetVulnerabilityModel, Line as LineModel, \
    RepositoryProductType as RepositoryProductTypeModel, Function as FunctionModel, Profile, ProfileCWE, Weakness


class GrapheneCount(graphene.ObjectType):
    key = graphene.String()
    value = graphene.Int()


class ProfileObject(SQLAlchemyObjectType):
    class Meta:
        model = Profile
        use_connection = True

    id = graphene.Int()
    name = graphene.String()

    def resolve_id(self, info):
        return self.id

    def resolve_name(self, info):
        return self.name


class ProfileCWEObject(SQLAlchemyObjectType):
    class Meta:
        model = ProfileCWE
        use_connection = True


class RepositoryProductType(SQLAlchemyObjectType):
    class Meta:
        model = RepositoryProductTypeModel
        use_connection = True


class Line(SQLAlchemyObjectType):
    class Meta:
        model = LineModel
        use_connection = True


class Function(SQLAlchemyObjectType):
    class Meta:
        model = FunctionModel
        use_connection = True


class DatasetVulnerability(SQLAlchemyObjectType):
    class Meta:
        model = DatasetVulnerabilityModel
        use_connection = True


class WeaknessObject(SQLAlchemyObjectType):
    class Meta:
        model = Weakness
        use_connection = True

    id = graphene.Int()
    tuple = graphene.String()

    def resolve_id(self, info):
        return self.id

    def resolve_tuple(self, info):
        return self.tuple


class Dataset(SQLAlchemyObjectType):
    class Meta:
        model = DatasetModel
        use_connection = True

    id = graphene.Int()
    name = graphene.String()
    description = graphene.String()
    vulnerabilities = graphene.List(lambda: Vulnerability)
    size = graphene.Int()

    def resolve_vulnerabilities(self, info):
        vuln_ids = DatasetVulnerability.get_query(info).filter_by(dataset_id=self.id).all()
        return Vulnerability.get_query(info).filter(VulnerabilityModel.id.in_([vuln.vulnerability_id for vuln in vuln_ids])).all()

    def resolve_id(self, info):
        return self.id

    def resolve_name(self, info):
        return self.name

    def resolve_description(self, info):
        return self.description

    def resolve_size(self, info):
        vuln_ids = DatasetVulnerability.get_query(info).filter_by(dataset_id=self.id).all()
        return len(vuln_ids)


class Grouping(SQLAlchemyObjectType):
    class Meta:
        model = GroupingModel
        use_connection = True


class RepositoryTopic(SQLAlchemyObjectType):
    class Meta:
        model = RepositoryTopicModel
        use_connection = True


class Topic(SQLAlchemyObjectType):
    class Meta:
        model = TopicModel
        use_connection = True

    def resolve_name(self, info):
        return self.name


class CommitFile(SQLAlchemyObjectType):
    class Meta:
        model = CommitFileModel
        use_connection = True

    id = graphene.String()
    filename = graphene.String()
    patch = graphene.String()
    content = graphene.String()

    def resolve_content(self, info):
        lines = Line.get_query(info).filter_by(commit_file_id=self.id).order_by(LineModel.number).all()
        return '\n'.join([line.content for line in lines])

    def resolve_patch(self, info):
        return self.patch

    def resolve_id(self, info):
        return self.id

    def resolve_filename(self, info):
        return self.filename


class ProductType(SQLAlchemyObjectType):
    class Meta:
        model = ProductTypeModel
        use_connection = True


class Product(SQLAlchemyObjectType):
    class Meta:
        model = ProductModel
        use_connection = True

    sw_type = graphene.String()
    configurations = graphene.List(lambda: Configuration)
    configurations_count = graphene.Int()
    vulnerabilities_count = graphene.Int()

    def resolve_sw_type(self, info):
        return ProductType.get_query(info).filter(self.product_type_id == ProductTypeModel.id).first().name

    def resolve_configurations(self, info):
        return self.configurations

    def resolve_configurations_count(self, info):
        return len(self.configurations)

    def resolve_vulnerabilities_count(self, info):
        return len(set([config.vulnerability_id for config in self.configurations]))


class Vendor(SQLAlchemyObjectType):
    class Meta:
        model = VendorModel
        use_connection = True

    products = graphene.List(lambda: Product)
    products_count = graphene.Int()
    configurations = graphene.List(lambda: Configuration)
    configurations_count = graphene.Int()
    vulnerabilities_count = graphene.Int()

    def resolve_products_count(self, info):
        return len(self.products)

    def resolve_configurations(self, info):
        return [config for product in self.products for config in product.configurations]

    def resolve_configurations_count(self, info):
        return len([config for product in self.products for config in product.configurations])

    def resolve_vulnerabilities_count(self, info):
        return len(set([config.vulnerability_id for product in self.products for config in product.configurations]))


class Configuration(SQLAlchemyObjectType):
    class Meta:
        model = ConfigurationModel
        use_connection = True


class ConfigurationVulnerability(SQLAlchemyObjectType):
    class Meta:
        model = ConfigurationVulnerabilityModel
        use_connection = True


class Commit(SQLAlchemyObjectType):
    class Meta:
        model = CommitModel
        use_connection = True

    files = graphene.List(lambda: CommitFile)

    def resolve_files(self, info):
        return self.files


class Repository(SQLAlchemyObjectType):
    class Meta:
        model = RepositoryModel
        use_connection = True

    commits = graphene.List(lambda: Commit)
    commits_count = graphene.Int()
    topics = graphene.List(graphene.String)
    software_type = graphene.String()
    vulnerability_profile = graphene.List(lambda: GrapheneCount)
    vulnerability_count = graphene.Int()

    def resolve_vulnerability_count(self, info):
        return len(set([c.vulnerability_id for c in self.commits]))

    def resolve_vulnerability_profile(self, info):
        vuln_ids = [c.vulnerability_id for c in self.commits if c.vulnerability_id is not None]
        vulns_query = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.vulnerability_id.in_(vuln_ids),
                                                              VulnerabilityCWEModel.vulnerability_id.isnot(None)).\
            group_by(VulnerabilityCWEModel.cwe_id).\
            with_entities(VulnerabilityCWEModel.cwe_id, sqlalchemy.func.count(VulnerabilityCWEModel.cwe_id))\

        return [GrapheneCount(key=k, value=v) for k, v in vulns_query.all()]

    def resolve_software_type(self, info):
        relationships = RepositoryProductType.get_query(info).filter_by(repository_id=self.id).first()

        if relationships:
            return ProductType.get_query(info).filter_by(id=relationships.product_type_id).first().name
        else:
            return None

    def resolve_topics(self, info):
        topic_ids = [t.topic_id for t in RepositoryTopic.get_query(info).filter(RepositoryTopicModel.repository_id == self.id).all()]
        return [t.name for t in Topic.get_query(info).filter(TopicModel.id.in_(topic_ids)).all()]

    def resolve_commits(self, info):
        return self.commits

    def resolve_commits_count(self, info):
        return len([c for c in self.commits if c.kind != "parent"])


class Tag(SQLAlchemyObjectType):
    class Meta:
        model = TagModel
        use_connection = True

    name = graphene.String()

    def resolve_name(self, info):
        return self.name


class Reference(SQLAlchemyObjectType):
    class Meta:
        model = ReferenceModel
        use_connection = True

    tags = graphene.List(lambda: Tag)

    def resolve_tags(self, info):
        tag_ids = ReferenceTag.get_query(info).filter(ReferenceTagModel.reference_id == self.id).all()
        return Tag.get_query(info).filter(TagModel.id.in_([tag.tag_id for tag in tag_ids])).all()


class ReferenceTag(SQLAlchemyObjectType):
    class Meta:
        model = ReferenceTagModel
        use_connection = True


class Abstraction(SQLAlchemyObjectType):
    class Meta:
        model = AbstractionModel
        use_connection = True

    name = graphene.String()


class Operation(SQLAlchemyObjectType):
    class Meta:
        model = OperationModel
        use_connection = True


class CWEOperation(SQLAlchemyObjectType):
    class Meta:
        model = CWEOperationModel
        use_connection = True


class Phase(SQLAlchemyObjectType):
    class Meta:
        model = PhaseModel
        use_connection = True


class CWEPhase(SQLAlchemyObjectType):
    class Meta:
        model = CWEPhaseModel
        use_connection = True


class BFClass(SQLAlchemyObjectType):
    class Meta:
        model = BFClassModel
        use_connection = True


class CWEBFClass(SQLAlchemyObjectType):
    class Meta:
        model = CWEBFClassModel
        use_connection = True


class VulnerabilityCWE(SQLAlchemyObjectType):
    class Meta:
        model = VulnerabilityCWEModel
        use_connection = True


class Vulnerability(SQLAlchemyObjectType):
    class Meta:
        model = VulnerabilityModel
        use_connection = True

    id = graphene.String()
    cwe_ids = graphene.List(lambda: CWE)
    references = graphene.List(lambda: Reference)
    commits = graphene.List(lambda: Commit)
    rootWeakness = graphene.String()

    def resolve_id(self, info):
        return self.id

    def resolve_commits(self, info):
        commits_query = Commit.get_query(info=info)
        commits_query = commits_query.filter(CommitModel.vulnerability_id == self.id)

        return commits_query.all()

    def resolve_rootWeakness(self, info):
        weakness = WeaknessObject.get_query(info=info).filter(Weakness.vulnerability_id == self.id).first()

        if weakness:
            return weakness.tuple

        return None

    def resolve_references(self, info):
        references_query = Reference.get_query(info=info)
        cwe_vuln_query = references_query.filter(ReferenceModel.vulnerability_id == self.id)

        return cwe_vuln_query.all()

    def resolve_cwe_ids(self, info):
        cwe_vuln_query = VulnerabilityCWE.get_query(info=info)
        cwe_vuln_query = cwe_vuln_query.filter(VulnerabilityCWEModel.vulnerability_id == self.id)

        cwes = []
        cwes_query = CWE.get_query(info=info)

        for cwe_vuln in cwe_vuln_query.all():
            cwe = cwes_query.filter(CWEModel.id == cwe_vuln.cwe_id)

            if cwe.first():
                cwes.append(cwe.first())

        return cwes


class CWE(SQLAlchemyObjectType):
    class Meta:
        model = CWEModel
        use_connection = True
        filter_fields = ["id"]

    abstraction = graphene.String()
    operations = graphene.List(lambda: Operation, name=graphene.String())
    phases = graphene.List(lambda: Phase, name=graphene.String(), acronym=graphene.String())
    bf_classes = graphene.List(lambda: BFClass, name=graphene.String())

    def resolve_id(self, info):
        return self.id

    def resolve_abstraction(self, info):
        query = Abstraction.get_query(info=info)
        query = query.filter(AbstractionModel.id == self.abstraction_id)

        return query.first().name

    def resolve_operations(self, info, name=None):
        cwe_op_query = CWEOperation.get_query(info=info)
        cwe_op_query = cwe_op_query.filter(CWEOperationModel.cwe_id == self.id)

        ops = []
        ops_query = Operation.get_query(info=info)

        for cwe_op in cwe_op_query.all():
            ops_query = ops_query.filter(OperationModel.id == cwe_op.operation_id)

            if name:
                ops_query = ops_query.filter(OperationModel.name == name)

            if ops_query.first():
                ops.append(ops_query.first())

        return ops

    def resolve_phases(self, info, name=None, acronym=None):
        phases = []
        cwe_phase_query = CWEPhase.get_query(info=info)
        cwe_phase_query = cwe_phase_query.filter(CWEPhaseModel.cwe_id == self.id)
        phases_query = Phase.get_query(info=info)

        for cwe_phase in cwe_phase_query.all():
            phases_query = phases_query.filter(PhaseModel.id == cwe_phase.phase_id)

            if name:
                phases_query = phases_query.filter(PhaseModel.name == name)
            if acronym:
                phases_query = phases_query.filter(PhaseModel.acronym == acronym)

            if phases_query.first():
                phases.append(phases_query.first())

        return phases

    def resolve_bf_class(self, info, name=None):
        bf_classes = []
        cwe_bf_class_query = CWEBFClass.get_query(info=info)
        cwe_bf_class_query = cwe_bf_class_query.filter(CWEBFClassModel.cwe_id == self.id)
        bf_classes_query = BFClass.get_query(info=info)

        for cwe_bf_class in cwe_bf_class_query.all():
            bf_classes_query = bf_classes_query.filter(BFClassModel.id == cwe_bf_class.bf_class_id)

            if name:
                bf_classes_query = bf_classes_query.filter(PhaseModel.name == name)

            if bf_classes_query.first():
                bf_classes.append(bf_classes_query.first())

        return bf_classes
