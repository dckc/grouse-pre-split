select domain from cms_ccw where 'dep' = 'cms_ccw_spec.sql';

truncate table "&&I2B2STAR".patient_dimension;

insert
into "&&I2B2STAR".patient_dimension
  (
    patient_num
  , sex_cd
  , race_cd
  , vital_status_cd
  , birth_date
  , death_date
  , age_in_years_num
    -- TODO:    , state_cd
  , import_date
  , upload_id
    -- TODO:    , download_date
  , sourcesystem_cd
  )
select pat_map.patient_num
, cms_pat_dim.sex_cd
, cms_pat_dim.race_cd
, cms_pat_dim.vital_status_cd
, cms_pat_dim.birth_date
, cms_pat_dim.death_date
, cms_pat_dim.age_in_years_num
, sysdate as import_date
, :upload_id
, cms_ccw.domain as sourcesystem_cd
from cms_patient_dimension cms_pat_dim
cross join cms_ccw
join
  (select patient_ide bene_id
  , patient_num
  from "&&I2B2STAR".patient_mapping pat_map
  join cms_ccw
  on patient_ide_source = cms_ccw.domain
  ) pat_map on pat_map.bene_id = cms_pat_dim.bene_id ;

select count( *) loaded_record
from "&&I2B2STAR".patient_dimension;
