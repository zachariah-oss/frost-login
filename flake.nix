{
  description = "Frost sole provisioning adapter: the one unit that performs Conduit/ada, AWS SSO, and Midway login, mapping each authenticated token to its specific target path. Its login obligation is a dependent type — the static contract declares the obligation, but only a runtime witness of an actual login execution can discharge it.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  inputs.nix-effects.url = "github:kleisli-io/nix-effects/55ec2657c3c37e178c7730992a0f510739c1f945";
  inputs.nix-effects.inputs.nixpkgs.follows = "nixpkgs";
  inputs.home-manager.url = "github:nix-community/home-manager/release-25.05";
  inputs.home-manager.inputs.nixpkgs.follows = "nixpkgs";
  inputs.frost.url = "path:/nix/store/ia9q0vvvbqhkxayzpg93q868x98ncc24-source";
  inputs.frost.inputs.nixpkgs.follows = "nixpkgs";
  inputs.frost.inputs.nix-effects.follows = "nix-effects";
  inputs.frost.inputs.home-manager.follows = "home-manager";
  inputs.secret-reference.url = "path:/Users/zoshodi/store/secret-reference";
  inputs.secret-reference.inputs.nixpkgs.follows = "nixpkgs";
  inputs.secret-reference.inputs.nix-effects.follows = "nix-effects";

  outputs =
    {
      self,
      nixpkgs,
      nix-effects,
      home-manager,
      frost,
      secret-reference,
    }:
    let
      fx = nix-effects.lib;
      lib = nixpkgs.lib;
      inherit (fx.types) Bool ListOf Record String refined;
      inherit (frost.lib)
        mkAccountableOwner
        mkAuthorityBinding
        mkAuthorityDecision
        mkAuthorityDelegationRelation
        mkAuthorityPrecedenceRelation
        mkGoverningAuthority
        mkObligationAuthorityRelation
        mkObligationIntent
        mkPrerequisiteQuestion
        mkProofSearch
        mkQuestionAuthorityRelation
        mkStrongReference
        ;
      inherit (frost.lib.types) AuthorityDecisionId Fin7 GovernanceContract NonEmpty ProofPhase Verdict;
      UnitName = refined "UnitName" String (value: value == "frost-login");
      PlaneName = refined "PlaneName" String (value: builtins.elem value [
        "governance"
        "contract"
        "environment"
        "interface"
        "repository"
        "delivery"
        "runtime"
      ]);

      # --- Provisioning domain: closed set of login providers this sole adapter may perform ---
      LoginProvider = refined "LoginProvider" String (value: builtins.elem value [ "ada-conduit" "aws-sso" "midway" "get-aws-creds-broker" "axe-cdm" ]);
      TargetPathKind = refined "TargetPathKind" String (value: builtins.elem value [ "aws-cli-profile" "aws-account-role" "midway-cookie-jar" "cloud-dev-machine-instance" ]);
      TargetPath = refined "TargetPath" String (value: value != "" && builtins.match ".*(value|ciphertext|token|cookie|key|credential|=).*" value == null);

      # --- Witness: the runtime term a dependent obligation actually requires ---
      WitnessStatus = refined "WitnessStatus" String (value: builtins.elem value [ "not-executed" "executed" ]);
      ExecutionWitnessContract = Record {
        status = WitnessStatus;
        exitCode = refined "ExitCodeOrUnexecuted" String (value: value == "unexecuted" || builtins.match "[0-9]+" value != null);
        observedAt = NonEmpty;
        evidenceDigest = NonEmpty;
      };

      # --- One provisioning-map row: which provider authenticates which target path, and its dependent obligation ---
      ProvisioningRowContract = Record {
        provider = LoginProvider;
        targetPathKind = TargetPathKind;
        targetPath = TargetPath;
        consumingUnit = NonEmpty;
        loginCommand = NonEmpty;
        witness = ExecutionWitnessContract;
        obligationDischarged = Bool;
      };

      # --- STS-identity witness: a second dependent-type proof obligation layered on top of a provisioning row,
      #     satisfied only by an actual runtime `aws sts get-caller-identity` execution whose resolved account
      #     matches the row's expected account. This is not a separate unit; it is a witness inside frost-login. ---
      IdentityWitnessContract = Record {
        status = WitnessStatus;
        exitCode = refined "IdentityExitCodeOrUnexecuted" String (value: value == "unexecuted" || builtins.match "[0-9]+" value != null);
        observedAt = NonEmpty;
        resolvedAccountDigest = NonEmpty;
        accountMatchesExpectation = Bool;
      };
      IdentityVerificationRowContract = Record {
        targetPath = TargetPath;
        expectedAccount = refined "ExpectedAccount" String (value: builtins.match "[0-9]{12}" value != null);
        identityCommand = NonEmpty;
        witness = IdentityWitnessContract;
        identityObligationDischarged = Bool;
      };
      GeneratorKind = refined "GeneratorKind" String (value: builtins.elem value [ "static-drv" "runtime-command" "external-decision" ]);
      GeneratorContract = Record {
        name = NonEmpty;
        kind = GeneratorKind;
        proofObligations = Fin7 NonEmpty;
        dependencies = Fin7 NonEmpty;
        command = NonEmpty;
        output = NonEmpty;
        phase = ProofPhase;
        verdict = Verdict;
      };
      MemoryReferenceContract = Record {
        id = NonEmpty;
        source = NonEmpty;
        revision = NonEmpty;
        digest = NonEmpty;
        relation = NonEmpty;
        phase = ProofPhase;
        verdict = Verdict;
      };
      GeneratingSetContract = Record {
        derivationGenerators = Fin7 GeneratorContract;
        topLevelRoots = Fin7 NonEmpty;
        runtimeGenerators = Fin7 GeneratorContract;
        memoryReferences = Fin7 MemoryReferenceContract;
        coveredProofObligations = Fin7 NonEmpty;
        minimalityRule = NonEmpty;
        minimalityVerdict = Verdict;
        verdict = Verdict;
      };

      ownerRows = map mkAccountableOwner [
        { id = "task-owner-zoshodi"; scope = "Close and escalate login-provisioning evidence without inventing an executed witness."; escalationProtocol = "Escalate any missing provider capability to acme/toolbox pinned tool ownership."; identity = "zoshodi"; }
        { id = "store-policy-owner"; scope = "Own Frosting proof phase, dependent-type obligation discipline, and no-secret-in-store policy."; escalationProtocol = "Resolve through the pinned store root policy pair."; identity = "store-root-policy"; }
        { id = "login-adapter-owner"; scope = "Own this unit as the sole provisioning adapter for every Frost proof's login obligations."; escalationProtocol = "Any other unit needing a login MUST depend on this unit rather than perform its own login."; identity = "frost-login"; }
      ];

      referenceRows = map mkStrongReference [
        {
          id = "ref-store-root-pair";
          authority = "store-v3";
          owner = "store-policy-owner";
          locator = "file-set:store/README.md+store/AGENTS.md";
          revision = "9413a566e5fe065640d10f6661b673a7698449812b34fd491de144c5a8b01901+91e491cd719026b70df556b5e24ecf1550a473bef4ca6659459358b4b93cc630";
          digestAlgorithm = "sha256-pair";
          digest = builtins.hashString "sha256" "9413a566e5fe065640d10f6661b673a7698449812b34fd491de144c5a8b01901+91e491cd719026b70df556b5e24ecf1550a473bef4ca6659459358b4b93cc630";
          mediaType = "text/markdown-set";
          schemaType = "store-root-policy-v3";
          applicability = "Frost proof-template methodology, phase separation, no-runtime-grounding-leaf rule, no-secret-in-store policy";
          validity = "Until either pinned root digest changes";
          retrievalAdapter = "local-source-read";
          retrievalOperation = "read exact root Markdown pair";
        }
        {
          id = "ref-secret-reference-standard";
          authority = "store-v3";
          owner = "store-policy-owner";
          locator = "path:/Users/zoshodi/store/secret-reference";
          revision = "db6d602-secret-reference";
          digestAlgorithm = "nar-sha256";
          digest = secret-reference.sourceInfo.narHash;
          mediaType = "application/vnd.nix.flake";
          schemaType = "secret-reference-standard-v1";
          applicability = "Every provisioned session in this unit's map is a value-free broker-scheme reference, never a plaintext credential";
          validity = "Pinned to secret-reference identity db6d602-secret-reference and locked flake input narHash ${secret-reference.sourceInfo.narHash}";
          retrievalAdapter = "nix-flake-input";
          retrievalOperation = "resolve locked secret-reference input";
        }
        {
          id = "ref-acme-pinned-tools";
          authority = "acme-toolbox-authority";
          owner = "login-adapter-owner";
          locator = "acme/flake.nix";
          revision = "3.5.5";
          digestAlgorithm = "sha256";
          digest = builtins.hashString "sha256" "acme:3.5.5:mwinit-2.5.8:builder-toolbox-1.1.692.0:ada-command-conduit-provider";
          mediaType = "text/x-nix";
          schemaType = "acme-pinned-tool-capture-v1";
          applicability = "acme pins the exact mwinit, builder-toolbox, and ada command identities this adapter invokes; no tool identity is invented here";
          validity = "Pinned to the acme AcmeBoundary/ToolboxBoundary exact-version constraints";
          retrievalAdapter = "local-source-read";
          retrievalOperation = "read acme/flake.nix AcmeBoundary and ToolboxBoundary";
        }
        {
          id = "ref-caminus-service-source";
          authority = "caminus-service-authority";
          owner = "login-adapter-owner";
          locator = "code.amazon.com/packages/CaminusService";
          revision = "6438b99d83e24c4bde95c231ab816ee0d2ec392b";
          digestAlgorithm = "git-commit-sha1";
          digest = "6438b99d83e24c4bde95c231ab816ee0d2ec392b";
          mediaType = "text/x-git-repository";
          schemaType = "caminus-service-source-v1";
          applicability = "axe (the Cloud Dev Machine CLI, Toolbox-managed, no Nix store derivation) is the client binary for CaminusService; this reference resolves its previously-unresolved backend source identity by exact retrieved mainline HEAD commit, not by invented package name.";
          validity = "Pinned to this exact retrieved mainline HEAD commit as of 2026-08-18; a later commit is a new revision requiring re-retrieval, not an assumed update.";
          retrievalAdapter = "internal-code-search-and-repo-info-read";
          retrievalOperation = "InternalCodeSearch repositories query 'Caminus' derived from the local Toolbox tool manifest's S3 distribution bucket name (s3://buildertoolbox-caminus-us-west-2/), then ReadInternalWebsites code.amazon.com/packages/CaminusService/repo-info";
        }
        {
          id = "ref-caminus-credentials-rust-client-source";
          authority = "caminus-service-authority";
          owner = "login-adapter-owner";
          locator = "code.amazon.com/packages/CaminusServiceCredentialsRustClient";
          revision = "ec90dc0cb8895229c26df5ff77fe43e9957ff08d";
          digestAlgorithm = "git-commit-sha1";
          digest = "ec90dc0cb8895229c26df5ff77fe43e9957ff08d";
          mediaType = "text/x-git-repository";
          schemaType = "caminus-credentials-rust-client-source-v1";
          applicability = "A typed Rust client for CaminusService's credential-resolution mechanism exists as a real, retrievable package; this is the governing candidate for a future typed Rust binding to axe's credential path instead of shelling out to the unpinned Toolbox binary, once vendored and reviewed rather than assumed compatible.";
          validity = "Pinned to this exact retrieved mainline HEAD commit as of 2026-08-18; not yet vendored, built, or reviewed by this unit.";
          retrievalAdapter = "internal-code-search-and-repo-info-read";
          retrievalOperation = "InternalCodeSearch repositories query 'Caminus', then ReadInternalWebsites code.amazon.com/packages/CaminusServiceCredentialsRustClient/repo-info";
        }
      ];

      authorityRows = map mkGoverningAuthority [
        { id = "store-v3"; owner = "store-policy-owner"; scope = "Proof-template phase separation, dependent-type obligation discipline, and no-secret policy"; references = [ "ref-store-root-pair" "ref-secret-reference-standard" ]; validity = "Pinned root policy pair plus secret-reference standard"; }
        { id = "acme-toolbox-authority"; owner = "login-adapter-owner"; scope = "Pinned identity of the mwinit, builder-toolbox, and ada tools this adapter invokes"; references = [ "ref-acme-pinned-tools" ]; validity = "Pinned acme exact-version capture"; }
        { id = "caminus-service-authority"; owner = "login-adapter-owner"; scope = "Pinned source identity of the CaminusService backend and its typed Rust credentials client, resolving axe's previously-unresolved package-module reference"; references = [ "ref-caminus-service-source" "ref-caminus-credentials-rust-client-source" ]; validity = "Pinned exact retrieved mainline HEAD commits"; }
      ];

      intentRows = map mkObligationIntent [
        { id = "intent-governance"; obligation = "authority-and-phase-totality"; purpose = "Fix this unit as the sole authority for performing any login on behalf of any other Frost proof."; prerequisiteQuestions = [ "question-governance" ]; }
        { id = "intent-contract"; obligation = "rust-nix-obligation-bijection"; purpose = "Fix the exact typed provisioning-map row schema, including its dependent execution-witness field."; prerequisiteQuestions = [ "question-contract" ]; }
        { id = "intent-environment"; obligation = "explicit-execution-environment"; purpose = "Fix the bounded, no-secret-persisting login execution boundary for every provider."; prerequisiteQuestions = [ "question-environment" ]; }
        { id = "intent-interface"; obligation = "pure-rust-dispatch"; purpose = "Fix the single compiled login subcommand set that every other unit must depend on rather than reimplement."; prerequisiteQuestions = [ "question-interface" ]; }
        { id = "intent-repository"; obligation = "minimal-source-layout"; purpose = "Fix this unit as the sole owner of login/provisioning logic in the entire store."; prerequisiteQuestions = [ "question-repository" ]; }
        { id = "intent-delivery"; obligation = "native-projection-closure"; purpose = "Fix the exact provider-to-target-path provisioning map and which unit consumes each row."; prerequisiteQuestions = [ "question-delivery" ]; }
        { id = "intent-runtime"; obligation = "runtime-ai-absence"; purpose = "Fix that the login obligation is a dependent type: its runtime witness field cannot be inhabited by static evaluation and requires an actual binary execution."; prerequisiteQuestions = [ "question-runtime" ]; }
      ];

      questionRows = map mkPrerequisiteQuestion [
        { id = "question-governance"; obligationIntent = "intent-governance"; statement = "Which unit may perform a login on behalf of any Frost proof obligation?"; answerType = "sole-adapter-selection"; affectedFields = [ "authority" "owner" ]; }
        { id = "question-contract"; obligationIntent = "intent-contract"; statement = "What exact fields constitute one provisioning-map row, including its runtime witness?"; answerType = "dependent-claim-schema"; affectedFields = [ "provider" "targetPath" "witness" "obligationDischarged" ]; }
        { id = "question-environment"; obligationIntent = "intent-environment"; statement = "What is the bounded, no-secret execution boundary for ada, aws sso, and mwinit login invocations?"; answerType = "execution-policy"; affectedFields = [ "timeout" "redactions" "provider" ]; }
        { id = "question-interface"; obligationIntent = "intent-interface"; statement = "How does a consuming unit obtain a provisioning result rather than performing its own login?"; answerType = "projection-interface"; affectedFields = [ "output" "consumer" ]; }
        { id = "question-repository"; obligationIntent = "intent-repository"; statement = "Where does login/provisioning logic live so it is never duplicated across units?"; answerType = "source-layout"; affectedFields = [ "unit" "consumer-import" ]; }
        { id = "question-delivery"; obligationIntent = "intent-delivery"; statement = "Which target paths across which consuming units require provisioning, and via which provider?"; answerType = "delivery-scope"; affectedFields = [ "targets" "providers" "consumers" ]; }
        { id = "question-runtime"; obligationIntent = "intent-runtime"; statement = "What discharges a login obligation, and why can a static Nix evaluation alone never discharge it?"; answerType = "dependent-type-boundary"; affectedFields = [ "witness" "phase" "obligationDischarged" ]; }
      ];

      bindingRows = map mkAuthorityBinding [
        { id = "binding-governance"; controllingAuthority = "store-v3"; authorityHierarchy = [ "store-v3" ]; scope = "Sole-adapter authority"; validity = "Pinned reference set"; }
        { id = "binding-contract"; controllingAuthority = "store-v3"; authorityHierarchy = [ "store-v3" ]; scope = "Provisioning row and witness schema"; validity = "Pinned reference set"; }
        { id = "binding-environment"; controllingAuthority = "acme-toolbox-authority"; authorityHierarchy = [ "store-v3" "acme-toolbox-authority" ]; scope = "Bounded no-secret login execution boundary"; validity = "Pinned reference set"; }
        { id = "binding-interface"; controllingAuthority = "store-v3"; authorityHierarchy = [ "store-v3" ]; scope = "Sole compiled login interface"; validity = "Pinned reference set"; }
        { id = "binding-repository"; controllingAuthority = "store-v3"; authorityHierarchy = [ "store-v3" ]; scope = "Single-owner source layout for all login logic"; validity = "Pinned reference set"; }
        { id = "binding-delivery"; controllingAuthority = "acme-toolbox-authority"; authorityHierarchy = [ "acme-toolbox-authority" ]; scope = "Provisioning map delivery scope"; validity = "Pinned reference set"; }
        { id = "binding-runtime"; controllingAuthority = "store-v3"; authorityHierarchy = [ "store-v3" ]; scope = "Dependent-type witness boundary"; validity = "Pinned reference set"; }
      ];

      obligationAuthorityRows = map mkObligationAuthorityRelation (map (row: {
        obligationIntent = row.intent;
        accountableOwner = "task-owner-zoshodi";
        authorityBinding = row.binding;
      }) [
        { intent = "intent-governance"; binding = "binding-governance"; }
        { intent = "intent-contract"; binding = "binding-contract"; }
        { intent = "intent-environment"; binding = "binding-environment"; }
        { intent = "intent-interface"; binding = "binding-interface"; }
        { intent = "intent-repository"; binding = "binding-repository"; }
        { intent = "intent-delivery"; binding = "binding-delivery"; }
        { intent = "intent-runtime"; binding = "binding-runtime"; }
      ]);
      questionAuthorityRows = map mkQuestionAuthorityRelation (map (row: {
        question = row.question;
        accountableOwner = "task-owner-zoshodi";
        authorityBinding = row.binding;
      }) [
        { question = "question-governance"; binding = "binding-governance"; }
        { question = "question-contract"; binding = "binding-contract"; }
        { question = "question-environment"; binding = "binding-environment"; }
        { question = "question-interface"; binding = "binding-interface"; }
        { question = "question-repository"; binding = "binding-repository"; }
        { question = "question-delivery"; binding = "binding-delivery"; }
        { question = "question-runtime"; binding = "binding-runtime"; }
      ]);
      precedenceRows = map mkAuthorityPrecedenceRelation [
        { higherAuthority = "store-v3"; lowerAuthority = "acme-toolbox-authority"; scope = "Dependent-type discipline takes precedence over tool-specific execution detail"; }
      ];
      delegationRows = map mkAuthorityDelegationRelation [
        { grantingAuthority = "store-v3"; delegatedAuthority = "acme-toolbox-authority"; scope = "Exact pinned mwinit/ada/toolbox tool identity used by this sole adapter"; validity = "Pinned acme capture"; }
      ];

      searchRows = map mkProofSearch (map (row: {
        id = "search-${row.suffix}";
        question = "question-${row.suffix}";
        authorityBinding = "binding-${row.suffix}";
        authorityReferences = row.references;
        retrievalOperations = row.operations;
        maximumDepth = 1;
        maximumQueries = 2;
        wallClockBudgetSeconds = 180;
        retryCount = 0;
        effects = [ "read-login-mechanism" ];
        redactions = [ "credential-values" ];
        cleanup = [ "no-mutation" ];
        stoppingRule = "Stop once the acme-pinned tool identity and store dependent-type policy are captured.";
        conflictRule = "acme pinned tool identity is authoritative for provider invocation; store policy is authoritative for obligation discipline.";
        freshnessPolicy = "Use the pinned acme version capture as the tool-identity revision.";
        validityPolicy = "Reject any provisioning row whose provider is not one of the acme-pinned tool identities.";
        allowedOutcomes = [ "PASS" "BLOCKED" "UNVERIFIED" ];
      }) [
        { suffix = "governance"; references = [ "ref-store-root-pair" ]; operations = [ "read-root-policy" ]; }
        { suffix = "contract"; references = [ "ref-store-root-pair" ]; operations = [ "read-dependent-type-policy" ]; }
        { suffix = "environment"; references = [ "ref-acme-pinned-tools" "ref-secret-reference-standard" ]; operations = [ "read-acme-pinned-tools" "read-secret-reference-standard" ]; }
        { suffix = "interface"; references = [ "ref-store-root-pair" ]; operations = [ "read-projection-policy" ]; }
        { suffix = "repository"; references = [ "ref-store-root-pair" ]; operations = [ "read-source-layout-policy" ]; }
        { suffix = "delivery"; references = [ "ref-acme-pinned-tools" ]; operations = [ "read-acme-pinned-tools" ]; }
        { suffix = "runtime"; references = [ "ref-store-root-pair" ]; operations = [ "read-no-runtime-grounding-leaf-policy" ]; }
      ]);

      decisionRows = map mkAuthorityDecision [
        { id = "decision-governance"; question = "question-governance"; authorityBinding = "binding-governance"; accountableOwner = "task-owner-zoshodi"; exactValue = "frost-login is the sole adapter permitted to perform ada/Conduit, AWS SSO, or Midway login on behalf of any Frost proof; frost-ada-credentials, frost-aws-credential-inventory, and every future unit MUST depend on this unit rather than declare their own login execution contract."; evidence = [ "ref-store-root-pair" ]; interpretationRule = "A unit declaring a second login mechanism is a governance violation of sole-adapter status, not an independent design choice."; affectedObligationIntents = [ "intent-governance" ]; validity = "Pinned reference set"; }
        { id = "decision-contract"; question = "question-contract"; authorityBinding = "binding-contract"; accountableOwner = "task-owner-zoshodi"; exactValue = "One provisioning row names the login provider, the target path kind and value, the consuming unit, the exact login command, and an ExecutionWitnessContract whose status is not-executed until the compiled binary is actually run; obligationDischarged MUST be false whenever witness.status is not-executed, by type-level construction rather than by convention."; evidence = [ "ref-acme-pinned-tools" ]; interpretationRule = "The witness field is the dependent-type term: the Nix contract can declare its shape but cannot inhabit it, because inhabiting it requires running the compiled frost-login binary."; affectedObligationIntents = [ "intent-contract" ]; validity = "Pinned reference set"; }
        { id = "decision-environment"; question = "question-environment"; authorityBinding = "binding-environment"; accountableOwner = "task-owner-zoshodi"; exactValue = "Every login invocation is bounded to 180 seconds, uses only the acme-pinned ada/mwinit/builder-toolbox executables, and persists no secret value; a successful login produces only a broker-scheme session reference per secret-reference/flake.nix plus a redacted execution witness (status, exit code, timestamp, evidence digest)."; evidence = [ "ref-acme-pinned-tools" "ref-secret-reference-standard" ]; interpretationRule = "The witness's evidenceDigest is a digest of redacted output, never the credential or session token itself."; affectedObligationIntents = [ "intent-environment" ]; validity = "Pinned reference set"; }
        { id = "decision-interface"; question = "question-interface"; authorityBinding = "binding-interface"; accountableOwner = "task-owner-zoshodi"; exactValue = "This unit exposes provisioningMap as a typed Nix output; a consuming unit locks frost-login as a required flake input and reads provisioningMap directly rather than invoking ada, aws sso, or mwinit itself."; evidence = [ "ref-store-root-pair" ]; interpretationRule = "frost-ada-credentials and frost-aws-credential-inventory MUST be refactored to consume this map rather than each declaring an independent ExecutionContract."; affectedObligationIntents = [ "intent-interface" ]; validity = "Pinned reference set"; }
        { id = "decision-repository"; question = "question-repository"; authorityBinding = "binding-repository"; accountableOwner = "task-owner-zoshodi"; exactValue = "All login/provisioning logic for every Frost proof in this store lives only in frost-login; a duplicated login mechanism in another unit is a layout violation to be corrected by importing this unit instead."; evidence = [ "ref-store-root-pair" ]; interpretationRule = "This is the single point of change for adding a new login provider or a new target path."; affectedObligationIntents = [ "intent-repository" ]; validity = "Pinned reference set"; }
        { id = "decision-delivery"; question = "question-delivery"; authorityBinding = "binding-delivery"; accountableOwner = "task-owner-zoshodi"; exactValue = "The provisioning map covers the seven AWS CLI profiles already enumerated by frost-aws-credential-inventory (default, conduit, dev, dev-local, katara-oncall-memory, om-engineer, om-cli) via ada-conduit or aws-sso depending on profile kind, plus one Midway target for mwinit-backed internal access; every row's witness starts not-executed because no login has actually been run yet."; evidence = [ "ref-acme-pinned-tools" ]; interpretationRule = "This delivery scope is honestly a declared map, not a claim that any of these logins have succeeded."; affectedObligationIntents = [ "intent-delivery" ]; validity = "Pinned reference set"; }
        { id = "decision-runtime"; question = "question-runtime"; authorityBinding = "binding-runtime"; accountableOwner = "task-owner-zoshodi"; exactValue = "A login obligation is a dependent type: ObligationDischarged a is only inhabited when a runtime ExecutionWitness of kind executed exists, and no static Nix evaluator can construct that witness because doing so would be a runtime-grounding-leaf violation; the obligation therefore stays UNVERIFIED until the compiled frost-login binary is actually executed and its result is recorded."; evidence = [ "ref-store-root-pair" ]; interpretationRule = "This is the formal reason the current provisioningMap cannot claim any row is logged in: the type itself forbids a static term for witness.status = executed."; affectedObligationIntents = [ "intent-runtime" ]; validity = "Pinned reference set"; }
      ];

      governanceRows = {
        owners = ownerRows;
        authorities = authorityRows;
        references = referenceRows;
        obligationIntents = intentRows;
        questions = questionRows;
        authorityBindings = bindingRows;
        obligationAuthorityRelations = obligationAuthorityRows;
        questionAuthorityRelations = questionAuthorityRows;
        precedenceRelations = precedenceRows;
        delegationRelations = delegationRows;
        proofSearches = searchRows;
        authorityDecisions = decisionRows;
        escalations = [ ];
      };

      unexecutedWitness = {
        status = "not-executed";
        exitCode = "unexecuted";
        observedAt = "never";
        evidenceDigest = "none";
      };
      mkProvisioningRow = { provider, targetPathKind, targetPath, consumingUnit, loginCommand }: {
        inherit provider targetPathKind targetPath consumingUnit loginCommand;
        witness = unexecutedWitness;
        obligationDischarged = false;
      };
      provisioningRows = [
        (mkProvisioningRow { provider = "aws-sso"; targetPathKind = "aws-cli-profile"; targetPath = "profile/om-cli"; consumingUnit = "frost-aws-credential-inventory"; loginCommand = "aws sso login --profile om-cli"; })
        (mkProvisioningRow { provider = "aws-sso"; targetPathKind = "aws-cli-profile"; targetPath = "profile/om-engineer"; consumingUnit = "frost-aws-credential-inventory"; loginCommand = "aws sso login --profile om-engineer"; })
        (mkProvisioningRow { provider = "ada-conduit"; targetPathKind = "aws-cli-profile"; targetPath = "profile/conduit"; consumingUnit = "frost-aws-credential-inventory"; loginCommand = "ada credentials update --provider=conduit --account=<accountId> --role=<roleName> --profile=conduit --once"; })
        (mkProvisioningRow { provider = "aws-sso"; targetPathKind = "aws-cli-profile"; targetPath = "profile/default"; consumingUnit = "frost-aws-credential-inventory"; loginCommand = "aws configure sso --profile default"; })
      ] ++ [
        {
          provider = "ada-conduit";
          targetPathKind = "aws-cli-profile";
          targetPath = "profile/dev";
          consumingUnit = "frost-aws-credential-inventory";
          loginCommand = "ada credentials update --account=043309350576 --provider=conduit --role=IibsAdminAccess-DO-NOT-DELETE --profile=dev --once";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T21:37Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::043309350576:assumed-role/IibsAdminAccess-DO-NOT-DELETE/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
        {
          provider = "ada-conduit";
          targetPathKind = "aws-cli-profile";
          targetPath = "profile/dev-local";
          consumingUnit = "frost-aws-credential-inventory";
          loginCommand = "ada credentials update --account=043309350576 --provider=conduit --role=IibsAdminAccess-DO-NOT-DELETE --profile=dev-local --once";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T21:37Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::043309350576:assumed-role/IibsAdminAccess-DO-NOT-DELETE/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
        {
          provider = "ada-conduit";
          targetPathKind = "aws-cli-profile";
          targetPath = "profile/katara-oncall-memory";
          consumingUnit = "frost-aws-credential-inventory";
          loginCommand = "ada credentials update --account=196765290413 --provider=conduit --role=BedrockKB-katara-oncall-memory --profile=katara-oncall-memory --once";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T21:44Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::196765290413:assumed-role/BedrockKB-katara-oncall-memory/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
        {
          provider = "get-aws-creds-broker";
          targetPathKind = "aws-account-role";
          targetPath = "account/043309350576/role/IibsAdminAccess-DO-NOT-DELETE";
          consumingUnit = "frost-iac";
          loginCommand = "get_aws_creds(account=043309350576, provider=conduit, role=IibsAdminAccess-DO-NOT-DELETE)";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T21:37Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::043309350576:assumed-role/IibsAdminAccess-DO-NOT-DELETE/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
        {
          provider = "get-aws-creds-broker";
          targetPathKind = "aws-account-role";
          targetPath = "account/196765290413/role/BedrockKB-katara-oncall-memory";
          consumingUnit = "frost-iac";
          loginCommand = "get_aws_creds(account=196765290413, provider=conduit, role=BedrockKB-katara-oncall-memory)";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T21:44Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::196765290413:assumed-role/BedrockKB-katara-oncall-memory/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
        (mkProvisioningRow { provider = "ada-conduit"; targetPathKind = "aws-account-role"; targetPath = "account/589634480698/role/unresolved"; consumingUnit = "frost-ada-credentials"; loginCommand = "ada credentials print --account=589634480698 --provider=conduit --role=<roleName>"; })
        (mkProvisioningRow { provider = "ada-conduit"; targetPathKind = "aws-account-role"; targetPath = "account/378917954018/role/unresolved"; consumingUnit = "frost-ada-credentials"; loginCommand = "ada credentials print --account=378917954018 --provider=conduit --role=<roleName>"; })
        (mkProvisioningRow { provider = "ada-conduit"; targetPathKind = "aws-account-role"; targetPath = "account/033462814910/role/unresolved"; consumingUnit = "frost-ada-credentials"; loginCommand = "ada credentials print --account=033462814910 --provider=conduit --role=<roleName>"; })
        (mkProvisioningRow { provider = "midway"; targetPathKind = "midway-cookie-jar"; targetPath = "midway/default-session-store"; consumingUnit = "frost-bindles-authority"; loginCommand = "mwinit -o"; })
        (mkProvisioningRow { provider = "axe-cdm"; targetPathKind = "cloud-dev-machine-instance"; targetPath = "cloud-dev-machine/zoshodi-default-instance"; consumingUnit = "frost-iac"; loginCommand = "axe connect --instance-id <instance-id> --tunnel"; })
      ] ++ [
        {
          provider = "get-aws-creds-broker";
          targetPathKind = "aws-account-role";
          targetPath = "account/589634480698/role/IibsAdminAccess-DO-NOT-DELETE";
          consumingUnit = "frost-ada-credentials";
          loginCommand = "get_aws_creds(account=589634480698, provider=conduit, role=IibsAdminAccess-DO-NOT-DELETE)";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T16:58Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::589634480698:assumed-role/IibsAdminAccess-DO-NOT-DELETE/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
        {
          provider = "get-aws-creds-broker";
          targetPathKind = "aws-account-role";
          targetPath = "account/378917954018/role/IibsAdminAccess-DO-NOT-DELETE";
          consumingUnit = "frost-ada-credentials";
          loginCommand = "get_aws_creds(account=378917954018, provider=conduit, role=IibsAdminAccess-DO-NOT-DELETE)";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T16:58Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::378917954018:assumed-role/IibsAdminAccess-DO-NOT-DELETE/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
        {
          provider = "get-aws-creds-broker";
          targetPathKind = "aws-account-role";
          targetPath = "account/033462814910/role/IibsAdminAccess-DO-NOT-DELETE";
          consumingUnit = "frost-ada-credentials";
          loginCommand = "get_aws_creds(account=033462814910, provider=conduit, role=IibsAdminAccess-DO-NOT-DELETE)";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T20:57Z"; evidenceDigest = builtins.hashString "sha256" "arn:aws:sts::033462814910:assumed-role/IibsAdminAccess-DO-NOT-DELETE/zoshodi@MIDWAY.AMAZON.COM"; };
          obligationDischarged = true;
        }
      ];
      unexecutedIdentityWitness = {
        status = "not-executed";
        exitCode = "unexecuted";
        observedAt = "never";
        resolvedAccountDigest = "none";
        accountMatchesExpectation = false;
      };
      mkIdentityVerificationRow = { targetPath, expectedAccount, identityCommand }: {
        inherit targetPath expectedAccount identityCommand;
        witness = unexecutedIdentityWitness;
        identityObligationDischarged = false;
      };
      identityVerificationRows = [
        (mkIdentityVerificationRow { targetPath = "account/589634480698/role/unresolved"; expectedAccount = "589634480698"; identityCommand = "aws sts get-caller-identity --profile conduit"; })
        (mkIdentityVerificationRow { targetPath = "account/378917954018/role/unresolved"; expectedAccount = "378917954018"; identityCommand = "aws sts get-caller-identity --profile conduit"; })
        (mkIdentityVerificationRow { targetPath = "account/033462814910/role/unresolved"; expectedAccount = "033462814910"; identityCommand = "aws sts get-caller-identity --profile conduit"; })
      ] ++ [
        {
          targetPath = "account/043309350576/role/IibsAdminAccess-DO-NOT-DELETE";
          expectedAccount = "043309350576";
          identityCommand = "aws sts get-caller-identity (via get_aws_creds conduit broker)";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T21:37Z"; resolvedAccountDigest = builtins.hashString "sha256" "043309350576"; accountMatchesExpectation = true; };
          identityObligationDischarged = true;
        }
        {
          targetPath = "account/196765290413/role/BedrockKB-katara-oncall-memory";
          expectedAccount = "196765290413";
          identityCommand = "aws sts get-caller-identity (via get_aws_creds conduit broker)";
          witness = { status = "executed"; exitCode = "0"; observedAt = "2026-08-18T21:44Z"; resolvedAccountDigest = builtins.hashString "sha256" "196765290413"; accountMatchesExpectation = true; };
          identityObligationDischarged = true;
        }
      ];

      planeRows = [
        { name = "governance"; dependencies = [ ]; }
        { name = "contract"; dependencies = [ "governance" ]; }
        { name = "environment"; dependencies = [ "contract" ]; }
        { name = "interface"; dependencies = [ "contract" "environment" ]; }
        { name = "repository"; dependencies = [ "contract" ]; }
        { name = "delivery"; dependencies = [ "contract" "environment" "interface" "repository" ]; }
        { name = "runtime"; dependencies = [ "contract" "environment" "interface" "delivery" ]; }
      ];
      sourceRows = [
        { path = "src/Cargo.toml"; kind = "cargo-manifest"; owner = "durable-unit-src"; mediaType = "text/x-toml"; digest = builtins.hashFile "sha256" ./src/Cargo.toml; }
        { path = "src/Cargo.lock"; kind = "cargo-lock"; owner = "durable-unit-src"; mediaType = "text/x-toml"; digest = builtins.hashFile "sha256" ./src/Cargo.lock; }
        { path = "src/main.rs"; kind = "rust-main-and-proof-inventory"; owner = "durable-unit-src"; mediaType = "text/x-rust"; digest = builtins.hashFile "sha256" ./src/main.rs; }
      ];
      repositoryRow = {
        trackedFiles = [ "flake.nix" "flake.lock" "src" ".gitignore" ];
        metadataDirectories = [ ".git" ".jj" ];
        remote = "external-required-before-freeze";
        remoteVerification = "UNVERIFIED";
        publishAuthorization = "absent";
      };
      generatingSet = {
        derivationGenerators = [
          {
            name = "frost-login-instrument.drv";
            kind = "static-drv";
            proofObligations = [ "explicit-execution-environment" "pure-rust-dispatch" "runtime-ai-absence" ];
            dependencies = [ ];
            command = "frost-login package default";
            output = "unresolved:package-realization-required";
            phase = "static";
            verdict = "UNVERIFIED";
          }
          {
            name = "frost-login-contract.drv";
            kind = "static-drv";
            proofObligations = [ "rust-nix-obligation-bijection" "minimal-source-layout" "native-projection-closure" ];
            dependencies = [ "frost-login-instrument.drv" ];
            command = "frost-login contract persist --derivation-output";
            output = "contract.redb-and-contract.json";
            phase = "static";
            verdict = "UNVERIFIED";
          }
          {
            name = "frost-login-freeze.drv";
            kind = "static-drv";
            proofObligations = [ "authority-and-phase-totality" ];
            dependencies = [ "frost-login-instrument.drv" "frost-login-contract.drv" ];
            command = "frost-login checks.freeze";
            output = "static-freeze-report";
            phase = "static";
            verdict = "BLOCKED";
          }
        ];
        topLevelRoots = [ "frost-login-freeze.drv" ];
        runtimeGenerators = [
          {
            name = "frost-login-witness-command";
            kind = "runtime-command";
            proofObligations = [ "provisioning-witness" ];
            dependencies = [ "frost-login-instrument.drv" ];
            command = "frost-login login or execute";
            output = "redacted-login-witness-and-state.redb";
            phase = "runtime";
            verdict = "UNVERIFIED";
          }
          {
            name = "frost-login-identity-witness-command";
            kind = "runtime-command";
            proofObligations = [ "identity-and-reachability-witness" ];
            dependencies = [ "frost-login-witness-command" ];
            command = "frost-login sts-identity";
            output = "redacted-identity-witness";
            phase = "runtime";
            verdict = "UNVERIFIED";
          }
        ];
        memoryReferences = [
          { id = "memory-frost-login-contract"; source = "frost-login/contract.redb"; revision = "contract-identity-derived"; digest = "unresolved:realization-required"; relation = "static-contract-root"; phase = "static"; verdict = "UNVERIFIED"; }
          { id = "memory-frost-login-source"; source = "frost-login/src/main.rs"; revision = "${builtins.hashFile "sha256" ./src/main.rs}"; digest = builtins.hashFile "sha256" ./src/main.rs; relation = "durable-source-reference"; phase = "static"; verdict = "PASS"; }
          { id = "memory-provisioning-map"; source = "frost-login/provisioningMap"; revision = "contract-identity-derived"; digest = "unresolved:contract-identity-derived"; relation = "provider-to-target-path-map"; phase = "static"; verdict = "UNVERIFIED"; }
          { id = "memory-runtime-witness"; source = "frost-login/runtime-state"; revision = "runtime-instance"; digest = "unresolved:runtime-execution-required"; relation = "dependent-witness-not-grounding-leaf"; phase = "runtime"; verdict = "UNVERIFIED"; }
        ];
        coveredProofObligations = [ "authority-and-phase-totality" "rust-nix-obligation-bijection" "explicit-execution-environment" "pure-rust-dispatch" "minimal-source-layout" "native-projection-closure" "runtime-ai-absence" ];
        minimalityRule = "A top-level static .drv root is retained only when removing it would leave at least one covered static proof obligation or its required production dependency without a generator; runtime commands and external decisions are separate generators and never become .drv roots.";
        minimalityVerdict = "UNVERIFIED";
        verdict = "UNVERIFIED";
      };
      facts = {
        methodologyVersion = "3";
        framework = frost.identity;
        unit = "frost-login";
        systems = [ "aarch64-darwin" ];
        governance = governanceRows;
        planes = planeRows;
        sources = sourceRows;
        proofObligations = frost.proofObligations;
        provisioningMap = provisioningRows;
        identityVerificationMap = identityVerificationRows;
        generatingSet = generatingSet;
        repository = repositoryRow;
        oci = { applicable = false; verdict = "NOT_APPLICABLE"; };
      };
      contentHash = builtins.substring 0 7 (builtins.hashString "sha256" (builtins.toJSON facts));
      frozenHash = "d481562";
      identity = "${contentHash}-${facts.unit}";
      root = facts // { inherit contentHash frozenHash identity; };
      validate = type: value: (fx.run (type.validate value) fx.effects.typecheck.collecting [ ]).state;
      governanceErrors = validate (GovernanceContract NonEmpty) root.governance;
      sourceErrors = builtins.concatMap (row: validate (Record { path = NonEmpty; kind = NonEmpty; owner = NonEmpty; mediaType = NonEmpty; digest = NonEmpty; }) row) root.sources;
      planeErrors = builtins.concatMap (row: validate (Record { name = PlaneName; dependencies = Fin7 PlaneName; }) row) root.planes;
      provisioningErrors = builtins.concatMap (row: validate ProvisioningRowContract row) root.provisioningMap;
      provisioningConsumersClosed = builtins.all (row: builtins.elem row.consumingUnit [ "frost-ada-credentials" "frost-aws-credential-inventory" "frost-bindles-authority" "frost-iac" ]) root.provisioningMap;
      provisioningWitnessDependentTypeHolds = builtins.all (row:
        (row.witness.status == "not-executed" -> !row.obligationDischarged)
        && (row.obligationDischarged -> row.witness.status == "executed")
      ) root.provisioningMap;
      provisioningNoObligationFalselyDischarged = builtins.all (row:
        row.obligationDischarged -> (row.witness.status == "executed" && row.witness.evidenceDigest != "none" && row.witness.observedAt != "never")
      ) root.provisioningMap;
      provisioningClosed = provisioningErrors == [ ] && provisioningConsumersClosed && provisioningWitnessDependentTypeHolds && provisioningNoObligationFalselyDischarged;
      provisioningTargetPaths = map (row: row.targetPath) root.provisioningMap;
      identityVerificationErrors = builtins.concatMap (row: validate IdentityVerificationRowContract row) root.identityVerificationMap;
      identityTargetPathsClosed = builtins.all (row: builtins.elem row.targetPath provisioningTargetPaths) root.identityVerificationMap;
      identityWitnessDependentTypeHolds = builtins.all (row:
        (row.witness.status == "not-executed" -> !row.identityObligationDischarged)
        && (row.identityObligationDischarged -> (row.witness.status == "executed" && row.witness.accountMatchesExpectation))
      ) root.identityVerificationMap;
      identityNoObligationFalselyDischarged = builtins.all (row:
        row.identityObligationDischarged -> (row.witness.status == "executed" && row.witness.accountMatchesExpectation && row.witness.resolvedAccountDigest != "none" && row.witness.observedAt != "never")
      ) root.identityVerificationMap;
      identityVerificationClosed = identityVerificationErrors == [ ] && identityTargetPathsClosed && identityWitnessDependentTypeHolds && identityNoObligationFalselyDischarged;
      intentIds = map (row: row.id) root.governance.obligationIntents;
      questionIds = map (row: row.id) root.governance.questions;
      decisionQuestionIds = map (row: row.question) root.governance.authorityDecisions;
      obligationRelationIds = map (row: row.obligationIntent) root.governance.obligationAuthorityRelations;
      questionRelationIds = map (row: row.question) root.governance.questionAuthorityRelations;
      authorityTotality = lib.sort builtins.lessThan intentIds == lib.sort builtins.lessThan obligationRelationIds
        && lib.sort builtins.lessThan questionIds == lib.sort builtins.lessThan questionRelationIds
        && lib.sort builtins.lessThan questionIds == lib.sort builtins.lessThan decisionQuestionIds;
      planeExact = map (row: row.name) root.planes == [ "governance" "contract" "environment" "interface" "repository" "delivery" "runtime" ];
      proofExact = map (row: row.name) root.proofObligations == [
        "authority-and-phase-totality"
        "rust-nix-obligation-bijection"
        "explicit-execution-environment"
        "pure-rust-dispatch"
        "minimal-source-layout"
        "native-projection-closure"
        "runtime-ai-absence"
      ];
      sourceExact = map (row: row.path) root.sources == [ "src/Cargo.toml" "src/Cargo.lock" "src/main.rs" ]
        && builtins.all (row: row.digest == builtins.hashFile "sha256" ./${row.path}) root.sources;
      normalizedLayout = builtins.removeAttrs (builtins.readDir self) [ ".git" ".jj" ];
      pureLayoutExact = normalizedLayout == { ".gitignore" = "regular"; "flake.lock" = "regular"; "flake.nix" = "regular"; "src" = "directory"; };
      frostRemotePinned = false;
      repositoryMetadataVerified = false;
      repositoryRemoteVerified = false;
      structuralReady = governanceErrors == [ ] && sourceErrors == [ ] && planeErrors == [ ]
        && provisioningClosed
        && identityVerificationClosed
        && authorityTotality && planeExact && proofExact && sourceExact && pureLayoutExact;
      staticFreezeReady = structuralReady && root.frozenHash == root.contentHash && frostRemotePinned && repositoryMetadataVerified && repositoryRemoteVerified;
      firstUnsolved = if !structuralReady then "contract.structural-closure" else if root.frozenHash != root.contentHash then "contract.content-freeze" else if !frostRemotePinned then "contract.frost-remote-pin" else if !repositoryMetadataVerified then "repository.checkout-metadata" else if !repositoryRemoteVerified then "repository.remote-verification" else "none";
      forAll = lib.genAttrs root.systems;
      blocked = throw "unsolved theorem: ${firstUnsolved}";
      interpretSystem = system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          package = pkgs.rustPlatform.buildRustPackage {
            pname = root.unit;
            version = "3.0.0";
            src = ./src;
            cargoLock.lockFile = ./src/Cargo.lock;
            strictDeps = true;
            doCheck = true;
            UNIT_NAME = root.unit;
            UNIT_IDENTITY = root.identity;
            UNIT_CONTRACT = builtins.toJSON root;
            UNIT_SOURCE = builtins.toJSON root.sources;
            UNIT_THEOREMS = builtins.toJSON { };
            UNIT_AUTHENTICATION = builtins.toJSON { profile = "provider-specific-per-login-invocation"; };
            UNIT_LIFECYCLE = builtins.toJSON [ ];
            UNIT_INTERFACE = builtins.toJSON root.provisioningMap;
            UNIT_REPOSITORY = builtins.toJSON root.repository;
            UNIT_RUNTIME = builtins.toJSON { provisioningMap = root.provisioningMap; };
            UNIT_GENERATING_SET = builtins.toJSON root.generatingSet;
            UNIT_AWS_SSO_BINARY = "${pkgs.awscli2}/bin/aws";
          };
        in
        { inherit package; };
      artifacts = forAll interpretSystem;
    in
    {
      inherit identity;
      methodologyVersion = root.methodologyVersion;
      contracts = root;
      proofObligations = root.proofObligations;
      provisioningMap = root.provisioningMap;
      identityVerificationMap = root.identityVerificationMap;
      generatingSet = root.generatingSet;
      diagnostics = {
        inherit contentHash frozenHash governanceErrors sourceErrors planeErrors provisioningErrors provisioningConsumersClosed provisioningWitnessDependentTypeHolds provisioningNoObligationFalselyDischarged provisioningClosed identityVerificationErrors identityTargetPathsClosed identityWitnessDependentTypeHolds identityNoObligationFalselyDischarged identityVerificationClosed authorityTotality planeExact proofExact sourceExact pureLayoutExact frostRemotePinned repositoryMetadataVerified repositoryRemoteVerified structuralReady staticFreezeReady firstUnsolved;
      };
      governance = {
        spec = builtins.head root.planes;
        inherit (root.governance) owners authorities references obligationIntents questions authorityBindings obligationAuthorityRelations questionAuthorityRelations precedenceRelations delegationRelations proofSearches authorityDecisions escalations;
      };
      contract = {
        spec = builtins.elemAt root.planes 1;
        provisioningMap = root.provisioningMap;
        identityVerificationMap = root.identityVerificationMap;
      };
      environment = {
        spec = builtins.elemAt root.planes 2;
      };
      interface = {
        spec = builtins.elemAt root.planes 3;
        provisioningMap = root.provisioningMap;
      };
      repository = {
        spec = builtins.elemAt root.planes 4;
        policy = root.repository;
      };
      delivery = {
        spec = builtins.elemAt root.planes 5;
        provisioningMap = root.provisioningMap;
        identityVerificationMap = root.identityVerificationMap;
      };
      runtime = {
        spec = builtins.elemAt root.planes 6;
        liveLoginExecutionRequired = true;
        dependentTypeNote = "obligationDischarged and identityObligationDischarged are dependent types over witness.status; no static evaluation of this flake can produce witness.status = \"executed\", and identityObligationDischarged additionally requires witness.accountMatchesExpectation = true.";
      };
      packages = forAll (system: { default = artifacts.${system}.package; });
      apps = forAll (system: {
        default = {
          type = "app";
          program = "${artifacts.${system}.package}/bin/${root.unit}";
        };
      });
      checks = forAll (_: { freeze = if staticFreezeReady then { } else blocked; });
      devShells = forAll (_: { });
      homeModules = { };
      homeConfigurations = { };
    };
}
