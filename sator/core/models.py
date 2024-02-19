import hashlib
from typing import List

import pandas as pd

from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy_utils import create_database, database_exists
from flask_sqlalchemy import SQLAlchemy

from sator.core.exc import SatorError

db = SQLAlchemy()


class Operation(db.Model):
    __tablename__ = "operation"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    cwes = db.relationship('CWE', secondary="cwe_operation", backref='operations')

    @staticmethod
    def populate(tables_path: Path):
        operations_df = pd.read_csv(f'{tables_path}/operations.csv')
        db.session.add_all([Operation(**row.to_dict()) for i, row in operations_df.iterrows()])
        db.session.commit()


class Phase(db.Model):
    __tablename__ = "phase"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    acronym = db.Column('acronym', db.String, nullable=False)
    url = db.Column('url', db.String, nullable=True)
    cwes = db.relationship('CWE', secondary="cwe_phase", backref='phases')

    @staticmethod
    def populate(tables_path: Path):
        phases_df = pd.read_csv(f'{tables_path}/phases.csv')
        db.session.add_all([Phase(**row.to_dict()) for i, row in phases_df.iterrows()])
        db.session.commit()


class BFClass(db.Model):
    __tablename__ = "bf_class"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    url = db.Column('url', db.String, nullable=True)
    cwes = db.relationship('CWE', secondary="cwe_bf_class", backref='bf_classes')

    @staticmethod
    def populate(tables_path: Path):
        classes_df = pd.read_csv(f'{tables_path}/bf_classes.csv')
        db.session.add_all([BFClass(**row.to_dict()) for i, row in classes_df.iterrows()])
        db.session.commit()


class Abstraction(db.Model):
    __tablename__ = "abstraction"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    cwes = db.relationship('CWE', backref='abstraction')

    @staticmethod
    def populate(tables_path: Path):
        abstractions_df = pd.read_csv(f'{tables_path}/abstractions.csv')
        db.session.add_all([Abstraction(**row.to_dict()) for i, row in abstractions_df.iterrows()])
        db.session.commit()


class CWE(db.Model):
    __tablename__ = "cwe"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    url = db.Column('url', db.String, nullable=False)
    abstraction_id = db.Column(db.Integer, db.ForeignKey('abstraction.id'))
    vulnerabilities = db.relationship('Vulnerability', secondary="vulnerability_cwe", backref='cwes')

    @staticmethod
    def populate(tables_path: Path):
        cwes_df = pd.read_csv(f'{tables_path}/cwes.csv')
        db.session.add_all([CWE(**row.to_dict()) for i, row in cwes_df.iterrows()])
        db.session.commit()

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'url': self.url, 'abstraction_id': self.abstraction_id}


class CWEOperation(db.Model):
    __tablename__ = "cwe_operation"
    __table_args__ = (
        db.PrimaryKeyConstraint('cwe_id', 'operation_id'),
    )

    cwe_id = db.Column('cwe_id', db.Integer, db.ForeignKey('cwe.id'))
    operation_id = db.Column('operation_id', db.Integer, db.ForeignKey('operation.id'))

    @staticmethod
    def populate(tables_path: Path):
        cwe_operation_df = pd.read_csv(f'{tables_path}/cwe_operation.csv')
        db.session.add_all([CWEOperation(**row.to_dict()) for i, row in cwe_operation_df.iterrows()])
        db.session.commit()


class CWEPhase(db.Model):
    __tablename__ = "cwe_phase"
    __table_args__ = (
        db.PrimaryKeyConstraint('cwe_id', 'phase_id'),
    )

    cwe_id = db.Column('cwe_id', db.Integer, db.ForeignKey('cwe.id'))
    phase_id = db.Column('phase_id', db.Integer, db.ForeignKey('phase.id'))

    @staticmethod
    def populate(tables_path: Path):
        cwe_phase_df = pd.read_csv(f'{tables_path}/cwe_phase.csv')
        db.session.add_all([CWEPhase(**row.to_dict()) for i, row in cwe_phase_df.iterrows()])
        db.session.commit()


class CWEBFClass(db.Model):
    __tablename__ = "cwe_bf_class"
    __table_args__ = (
        db.PrimaryKeyConstraint('cwe_id', 'bf_class_id'),
    )

    cwe_id = db.Column('cwe_id', db.Integer, db.ForeignKey('cwe.id'))
    bf_class_id = db.Column('bf_class_id', db.Integer, db.ForeignKey('bf_class.id'))

    @staticmethod
    def populate(tables_path: Path):
        cwe_class_df = pd.read_csv(f'{tables_path}/cwe_class.csv')
        db.session.add_all([CWEBFClass(**row.to_dict()) for i, row in cwe_class_df.iterrows()])
        db.session.commit()


class Tag(db.Model):
    __tablename__ = "tag"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    references = db.relationship("Reference", secondary="reference_tag", backref='tags')

    @staticmethod
    def populate(tables_path: Path):
        tags_df = pd.read_csv(f'{tables_path}/tags.csv')
        db.session.add_all([Tag(**row.to_dict()) for i, row in tags_df.iterrows()])
        db.session.commit()


class Reference(db.Model):
    __tablename__ = "reference"

    id = db.Column('id', db.String, primary_key=True)
    url = db.Column('url', db.String, nullable=False)
    vulnerability_id = db.Column(db.String, db.ForeignKey('vulnerability.id'))


class ReferenceTag(db.Model):
    __tablename__ = 'reference_tag'
    __table_args__ = (
        db.PrimaryKeyConstraint('reference_id', 'tag_id'),
    )

    reference_id = db.Column('reference_id', db.String, db.ForeignKey('reference.id'))
    tag_id = db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))


class Commit(db.Model):
    __tablename__ = "commit"

    id = db.Column('id', db.String, primary_key=True)
    sha = db.Column('sha', db.String, nullable=False)
    url = db.Column('url', db.String, nullable=False)
    kind = db.Column('kind', db.String, nullable=False)
    date = db.Column('date', db.DateTime, nullable=True)
    state = db.Column('state', db.String, nullable=True)
    author = db.Column('author', db.String, nullable=True)
    message = db.Column('message', db.String, nullable=True)
    changes = db.Column('changes', db.Integer, nullable=True)
    available = db.Column('available', db.Boolean, nullable=True)
    additions = db.Column('additions', db.Integer, nullable=True)
    deletions = db.Column('deletions', db.Integer, nullable=True)
    files_count = db.Column('files_count', db.Integer, nullable=True)
    parents_count = db.Column('parents_count', db.Integer, nullable=True)
    repository_id = db.Column(db.String, db.ForeignKey('repository.id'))
    vulnerability_id = db.Column(db.String, db.ForeignKey('vulnerability.id'))
    files = db.relationship("CommitFile", backref="commit")


class CommitFile(db.Model):
    __tablename__ = "commit_file"

    id = db.Column('id', db.String, primary_key=True)
    filename = db.Column('filename', db.String, nullable=False)
    additions = db.Column('additions', db.Integer, nullable=False)
    deletions = db.Column('deletions', db.Integer, nullable=False)
    changes = db.Column('changes', db.Integer, nullable=False)
    status = db.Column('status', db.String, nullable=False)
    extension = db.Column('extension', db.String, nullable=True)
    patch = db.Column('patch', db.String, nullable=True)
    raw_url = db.Column('raw_url', db.String, nullable=True)
    commit_id = db.Column(db.String, db.ForeignKey('commit.id'))
    lines = db.relationship("Line", backref="commit_file")


class Line(db.Model):
    __tablename__ = "line"

    id = db.Column('id', db.String, primary_key=True)
    number = db.Column('number', db.Integer, nullable=False)
    content = db.Column('content', db.String, nullable=False)
    commit_file_id = db.Column(db.String, db.ForeignKey('commit_file.id'))

    @staticmethod
    def add_all(lines):
        db.session.add_all(lines)
        db.session.commit()


class Label(db.Model):
    __tablename__ = "label"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)


class LineLabel(db.Model):
    __tablename__ = "line_label"
    __table_args__ = (
        db.PrimaryKeyConstraint('line_id', 'label_id'),
    )

    line_id = db.Column('line_id', db.String, db.ForeignKey('line.id'))
    label_id = db.Column('label_id', db.Integer, db.ForeignKey('label.id'))


class Function(db.Model):
    __tablename__ = "function"

    id = db.Column('id', db.String, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    commit_file_id = db.Column(db.String, db.ForeignKey('commit_file.id'))
    start_line = db.Column('start_line', db.Integer, nullable=False)
    start_col = db.Column('start_col', db.Integer, nullable=False)
    end_line = db.Column('end_line', db.Integer, nullable=False)
    end_col = db.Column('end_col', db.Integer, nullable=False)
    size = db.Column('size', db.Integer, nullable=False)

    @staticmethod
    def add_all(functions):
        db.session.add_all(functions)
        db.session.commit()


class CommitParent(db.Model):
    __tablename__ = "commit_parent"
    __table_args__ = (
        db.PrimaryKeyConstraint('commit_id', 'parent_id'),
    )

    commit_id = db.Column('commit_id', db.String, db.ForeignKey('commit.id'))
    parent_id = db.Column('parent_id', db.String, db.ForeignKey('commit.id'))


class Repository(db.Model):
    __tablename__ = "repository"

    id = db.Column('id', db.String, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    owner = db.Column('owner', db.String, nullable=False)
    available = db.Column('available', db.Boolean, nullable=True)
    description = db.Column('description', db.String, nullable=True)
    language = db.Column('language', db.String, nullable=True)
    size = db.Column('size', db.Integer, nullable=True)
    watchers = db.Column('watchers', db.Integer, nullable=True)
    forks = db.Column('forks', db.Integer, nullable=True)
    stargazers = db.Column('stargazers', db.Integer, nullable=True)
    commits_count = db.Column('commits_count', db.Integer, nullable=True)
    commits = db.relationship("Commit", backref="repository")

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"<Repository {self.owner}/{self.name}>"


class Topic(db.Model):
    __tablename__ = "topic"

    id = db.Column('id', db.String, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    repositories = db.relationship("Repository", secondary="repository_topic", backref='topics')

    @staticmethod
    def populate(tables_path: Path):
        topics_df = pd.read_csv(f'{tables_path}/topics.csv')
        db.session.add_all([Topic(**row.to_dict()) for i, row in topics_df.iterrows()])
        db.session.commit()


class RepositoryTopic(db.Model):
    __tablename__ = 'repository_topic'
    __table_args__ = (
        db.PrimaryKeyConstraint('repository_id', 'topic_id'),
    )

    repository_id = db.Column('repository_id', db.String, db.ForeignKey('repository.id'))
    topic_id = db.Column('topic_id', db.String, db.ForeignKey('topic.id'))


class Vulnerability(db.Model):
    __tablename__ = "vulnerability"

    id = db.Column('id', db.String, primary_key=True)
    description = db.Column('description', db.String, nullable=True)
    assigner = db.Column('assigner', db.String, nullable=False)
    severity = db.Column('severity', db.String, nullable=True)
    exploitability = db.Column('exploitability', db.Float, nullable=True)
    impact = db.Column('impact', db.Float, nullable=True)
    published_date = db.Column('published_date', db.DateTime, nullable=False)
    last_modified_date = db.Column('last_modified_date', db.DateTime, nullable=False)
    references = db.relationship("Reference", backref="vulnerability")
    configurations = db.relationship("Configuration", backref="vulnerability")


class VulnerabilityCWE(db.Model):
    __tablename__ = 'vulnerability_cwe'
    __table_args__ = (
        db.PrimaryKeyConstraint('vulnerability_id', 'cwe_id'),
    )

    vulnerability_id = db.db.Column('vulnerability_id', db.String, db.ForeignKey('vulnerability.id'))
    cwe_id = db.db.Column('cwe_id', db.Integer, db.ForeignKey('cwe.id'))


class Grouping(db.Model):
    __tablename__ = "grouping"
    __table_args__ = (
        db.PrimaryKeyConstraint('parent_id', 'child_id'),
    )

    parent_id = db.Column('parent_id', db.Integer, db.ForeignKey('cwe.id'))
    child_id = db.Column('child_id', db.Integer, db.ForeignKey('cwe.id'))

    @staticmethod
    def populate(tables_path: Path):
        grouping_df = pd.read_csv(f'{tables_path}/groupings.csv')
        db.session.add_all([Grouping(**row.to_dict()) for i, row in grouping_df.iterrows()])
        db.session.commit()


class Configuration(db.Model):
    __tablename__ = "configuration"

    id = db.Column('id', db.String, primary_key=True)
    vulnerable = db.Column('vulnerable', db.Boolean, nullable=True)
    part = db.Column('part', db.String, nullable=False)
    version = db.Column('version', db.String, nullable=True)
    update = db.Column('update', db.String, nullable=True)
    edition = db.Column('edition', db.String, nullable=True)
    language = db.Column('language', db.String, nullable=True)
    sw_edition = db.Column('sw_edition', db.String, nullable=True)
    target_sw = db.Column('target_sw', db.String, nullable=True)
    target_hw = db.Column('target_hw', db.String, nullable=True)
    other = db.Column('other', db.String, nullable=True)
    vulnerability_id = db.Column(db.String, db.ForeignKey('vulnerability.id'))
    vendor_id = db.Column(db.String, db.ForeignKey('vendor.id'))
    product_id = db.Column(db.String, db.ForeignKey('product.id'))


class Vendor(db.Model):
    __tablename__ = "vendor"

    id = db.Column('id', db.String, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    products = db.relationship("Product", backref="vendor")

    @staticmethod
    def populate(tables_path: Path):
        vendors = pd.read_csv(f'{tables_path}/vendor_product_type.csv')['vendor'].unique()

        for vendor in vendors:
            vendor_id = hashlib.md5(vendor.encode('utf-8')).hexdigest()
            db.session.add(Vendor(id=vendor_id, name=vendor))

        db.session.commit()


class Product(db.Model):
    __tablename__ = "product"

    id = db.Column('id', db.String, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    vendor_id = db.Column(db.String, db.ForeignKey('vendor.id'))
    product_type_id = db.Column(db.Integer, db.ForeignKey('product_type.id'))
    configurations = db.relationship("Configuration", backref="product")

    @staticmethod
    def populate(tables_path: Path):
        vendor_product_type = pd.read_csv(f'{tables_path}/vendor_product_type.csv')

        for g, _ in vendor_product_type.groupby(['vendor', 'product', 'product_type']):
            vendor, product, product_type = g
            vendor_id = hashlib.md5(vendor.encode('utf-8')).hexdigest()
            product_id = hashlib.md5(f"{vendor}:{product}".encode('utf-8')).hexdigest()
            db.session.add(Product(id=product_id, name=product, vendor_id=vendor_id, product_type_id=int(product_type)))

        db.session.commit()


class ProductType(db.Model):
    __tablename__ = "product_type"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    products = db.relationship("Product", backref="product_type")

    @staticmethod
    def populate(tables_path: Path):
        product_types_df = pd.read_csv(f'{tables_path}/product_type.csv')
        db.session.add_all([ProductType(**row.to_dict()) for i, row in product_types_df.iterrows()])
        db.session.commit()


class RepositoryProductType(db.Model):
    __tablename__ = 'repository_product_type'
    __table_args__ = (
        db.PrimaryKeyConstraint('repository_id', 'product_type_id'),
    )

    repository_id = db.Column('repository_id', db.String, db.ForeignKey('repository.id'))
    product_type_id = db.Column('product_type_id', db.Integer, db.ForeignKey('product_type.id'))

    def save(self):
        db.session.add(self)
        db.session.commit()


class ConfigurationVulnerability(db.Model):
    __tablename__ = 'configuration_vulnerability'
    __table_args__ = (
        db.PrimaryKeyConstraint('configuration_id', 'vulnerability_id'),
    )

    configuration_id = db.Column('configuration_id', db.String, db.ForeignKey('configuration.id'))
    vulnerability_id = db.Column('vulnerability_id', db.String, db.ForeignKey('vulnerability.id'))


class Dataset(db.Model):
    __tablename__ = "dataset"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    description = db.Column('description', db.String, nullable=True)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def remove(self):
        db.session.delete(self)
        db.session.commit()


class DatasetVulnerability(db.Model):
    __tablename__ = 'dataset_vulnerability'
    __table_args__ = (
        db.PrimaryKeyConstraint('dataset_id', 'vulnerability_id'),
    )

    dataset_id = db.Column('dataset_id', db.Integer, db.ForeignKey('dataset.id'))
    vulnerability_id = db.Column('vulnerability_id', db.String, db.ForeignKey('vulnerability.id'))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def remove(self):
        db.session.delete(self)
        db.session.commit()


class Profile(db.Model):
    __tablename__ = "profile"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String, nullable=False)
    has_code = db.Column('has_code', db.Boolean, nullable=False)
    has_exploit = db.Column('has_exploit', db.Boolean, nullable=False)
    has_advisory = db.Column('has_advisory', db.Boolean, nullable=False)
    start_year = db.Column('start_year', db.Integer, nullable=False)
    end_year = db.Column('end_year', db.Integer, nullable=True)
    start_score = db.Column('start_score', db.Float, nullable=False)
    end_score = db.Column('end_score', db.Float, nullable=False)
    min_changes = db.Column('min_changes', db.Integer, nullable=False)
    max_changes = db.Column('max_changes', db.Integer, nullable=True)
    min_files = db.Column('min_files', db.Integer, nullable=False)
    max_files = db.Column('max_files', db.Integer, nullable=True)
    # TODO: make it a relationship to hold more extensions
    extension = db.Column('extension', db.String, nullable=True)
    # TODO: should include the size / count

    def save(self):
        db.session.add(self)
        db.session.commit()


class ProfileCWE(db.Model):
    __tablename__ = 'profile_cwe'
    __table_args__ = (
        db.PrimaryKeyConstraint('profile_id', 'cwe_id'),
    )

    profile_id = db.Column('profile_id', db.Integer, db.ForeignKey('profile.id'))
    cwe_id = db.Column('cwe_id', db.Integer, db.ForeignKey('cwe.id'))

    def save(self):
        db.session.add(self)
        db.session.commit()


class Completion(db.Model):
    __tablename__ = "completion"

    id = db.Column('id', db.String, primary_key=True)
    object = db.Column('object', db.String, nullable=False)
    created = db.Column('created', db.Integer, nullable=False)
    model = db.Column('model', db.String, nullable=False)
    prompt = db.Column('prompt', db.String, nullable=False)
    completion = db.Column('completion', db.String, nullable=False)
    finish_reason = db.Column('finish_reason', db.String, nullable=False)
    prompt_tokens = db.Column('prompt_tokens', db.Integer, nullable=False)
    completion_tokens = db.Column('completion_tokens', db.Integer, nullable=False)
    total_tokens = db.Column('total_tokens', db.Integer, nullable=False)

    def save(self):
        db.session.add(self)
        db.session.commit()


class Weakness(db.Model):
    __tablename__ = "weakness"

    id = db.Column('id', db.Integer, primary_key=True)
    tuple = db.Column('tuple', db.String, nullable=True)
    vulnerability_id = db.Column('vulnerability_id', db.String, db.ForeignKey('vulnerability.id'))
    completion_id = db.Column('completion_id', db.String, db.ForeignKey('completion.id'))

    def save(self):
        db.session.add(self)
        db.session.commit()


def init_db_command(tables_path: Path, logger):
    """Clear the existing data and create new tables."""
    logger.info('Initializing the database.')

    if not Abstraction.query.all():
        Abstraction.populate(tables_path)
        logger.info("Populated 'abstractions' table.")

    if not Tag.query.all():
        Tag.populate(tables_path)
        logger.info("Populated 'tags' table.")

    if not Operation.query.all():
        Operation.populate(tables_path)
        logger.info("Populated 'operations' table.")

    if not Phase.query.all():
        Phase.populate(tables_path)
        logger.info("Populated 'phases' table.")

    if not BFClass.query.all():
        BFClass.populate(tables_path)
        logger.info("Populated 'bf_classes' table.")

    if not CWE.query.all():
        CWE.populate(tables_path)
        logger.info("Populated 'cwes' table.")

    if not CWEOperation.query.all():
        CWEOperation.populate(tables_path)

    if not CWEPhase.query.all():
        CWEPhase.populate(tables_path)

    if not CWEBFClass.query.all():
        CWEBFClass.populate(tables_path)

    if not ProductType.query.all():
        ProductType.populate(tables_path)
        logger.info("Populated 'product_types' table.")

    if not Vendor.query.all():
        Vendor.populate(tables_path)
        logger.info("Populated 'vendors' table.")

    if not Product.query.all():
        Product.populate(tables_path)
        logger.info("Populated 'products' table.")

    if not Grouping.query.all():
        Grouping.populate(tables_path)
        logger.info("Populated 'groupings' table.")


def shutdown_session(exception=None):
    db.session.remove()


def set_db(uri: str):
    engine = create_engine(uri)
    db.metadata.bind = engine
    Session = scoped_session(sessionmaker(bind=engine))
    db.session = Session
    db.query = db.session.query_property()


def init_db(uri: str, tables_path: Path, logger):
    set_db(uri)

    if not database_exists(uri):
        try:
            logger.info(f"Creating database")
            create_database(url=uri, encoding='utf8')
        except TypeError as te:
            raise SatorError(f"Could not create database {uri.split('@')}. {te}")

    # Create tables
    db.metadata.create_all()
    init_db_command(tables_path, logger)
