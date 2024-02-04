
const fs = require('fs');

const [inputFilePath, outputFilePath] = process.argv.slice(2);

if (!inputFilePath || !outputFilePath) {
  console.error("Please provide an input file path and an output file path.");
  process.exit(1);
}

const fileContents = fs.readFileSync(inputFilePath, 'utf-8');
const vxElectionDefinition = JSON.parse(fileContents);
const egElectionDefinition = {
  election_scope_id: "TestManifest",
  spec_version: "v2.0.0",
  type: vxElectionDefinition.title.indexOf('Primary') > -1 ? "primary" : "general",
  start_date: "start",
  end_date: "end",
  geopolitical_units: vxElectionDefinition.districts.map(d => {
    return {
      object_id: `district-${d.id}`,
      name: d.name,
      type: "district",
      contact_information: null
    };
  }),
  parties: vxElectionDefinition.parties.map(p => {
    return {
      object_id: `party-${p.id}`,
      name: p.name,
      abbreviation: p.abbrev,
      color: null,
      logo_uri: null,
    };
  }),
  candidates: vxElectionDefinition.contests.flatMap(contest => {
    if (!contest.candidates) {
      return []
    }

    return contest.candidates.map(cand => {
      return {
        object_id: `cand-${cand.id}`,
        name: cand.name,
        party_id: `party-${cand.partyIds[0]}`,
        image_url: null,
        is_write_in: false,
      }
    });
  }),
  contests: vxElectionDefinition.contests.map((contest, contest_num) => {
    return {
      object_id: `contest-${contest.id}`,
      sequence_order: contest_num + 1,
      electoral_district_id: `district-${contest.districtId}`,
      vote_variation: "one_of_m",
      number_elected: contest.seats,
	votes_allowed: contest.seats,
	name: `contest-${contest.id}`,
      ballot_selections: contest.candidates.map((cand, cand_num) => {
        return {
          object_id: `cand-${cand.id}`,
          sequence_order: cand_num + 1,
          candidate_id: `cand-${cand.id}`,
        };
      }),
      ballot_title: contest.title,
      ballot_subtitle: contest.section,
    }
  }),
  ballot_styles: vxElectionDefinition.ballotStyles.map(ballotStyle => {
    return {
      object_id: `ballot-style-${ballotStyle.id}`,
	geopolitical_unit_ids: ballotStyle.districts.map(d => `district-${d}`),
      party_ids: [`party-${ballotStyle.partyId}`],
      image_url: null
    };
  }),
  name: [],
  contact_information: {
    address_line: [],
    email: null,
    phone: "",
    name: "contact",
  }
}

fs.writeFileSync(outputFilePath, JSON.stringify(egElectionDefinition, null, 2));
