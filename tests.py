import csv
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas
import torch
import yaml

import comparator
import executor
import extractor


# =============================================================================
# extractor.py
# =============================================================================

class TestLoadDocuments(unittest.TestCase):
    """load_documents raises FileNotFoundError when given a path that does not exist."""

    def test_raises_file_not_found_for_nonexistent_paths(self):
        with self.assertRaises(FileNotFoundError):
            extractor.load_documents("/nonexistent/doc1.pdf", "/nonexistent/doc2.pdf")


class TestBuildZeroShotPrompt(unittest.TestCase):
    """build_zero_shot_prompt returns a prompt containing the injected requirements
    and the expected structural markers (category-per-line format, 'CIS EKS')."""

    @patch(
        "extractor._extract_requirement_list",
        return_value="2.1.1 Ensure audit logs are enabled\n3.1.1 Ensure worker nodes are hardened",
    )
    def test_prompt_contains_requirements_and_format_marker(self, _mock):
        prompt = extractor.build_zero_shot_prompt("dummy text")
        self.assertIn("CIS EKS", prompt)
        self.assertIn("Categories:", prompt)
        self.assertIn("2.1.1", prompt)
        self.assertIn("3.1.1", prompt)


class TestBuildFewShotPrompt(unittest.TestCase):
    """build_few_shot_prompt returns a prompt that includes hard-coded examples
    followed by the actual requirements extracted from the document."""

    @patch(
        "extractor._extract_requirement_list",
        return_value="3.2.1 Ensure kubelet is secured",
    )
    def test_prompt_contains_example_block_and_requirements(self, _mock):
        prompt = extractor.build_few_shot_prompt("dummy text")
        self.assertIn("Example:", prompt)
        # Verify at least one of the hard-coded example categories is present
        self.assertIn("Audit Logging", prompt)
        # Verify the injected requirement is present
        self.assertIn("3.2.1", prompt)


class TestBuildChainOfThoughtPrompt(unittest.TestCase):
    """build_chain_of_thought_prompt returns a prompt that guides the model
    through explicit reasoning steps before grouping."""

    @patch(
        "extractor._extract_requirement_list",
        return_value="4.1.1 Ensure RBAC is configured",
    )
    def test_prompt_contains_step_by_step_reasoning(self, _mock):
        prompt = extractor.build_chain_of_thought_prompt("dummy text")
        self.assertIn("step by step", prompt)
        # Chain-of-thought block must reference kubelet (domain hint)
        self.assertIn("kubelet", prompt.lower())
        # The extracted requirement must appear in the prompt
        self.assertIn("4.1.1", prompt)


class TestExtractKdesWithLlm(unittest.TestCase):
    """extract_kdes_with_llm returns a (dict, str) tuple whose dict mirrors what
    _parse_category_output returns when the model and parsing helpers are mocked."""

    @patch("extractor._parse_category_output", return_value={
        "element1": {
            "name": "Audit Logging",
            "requirements": ["2.1.1 Ensure audit logs are enabled"],
        }
    })
    @patch("extractor._extract_requirement_lookup", return_value={
        "2.1.1": "Ensure audit logs are enabled"
    })
    @patch("extractor._get_model_and_tokenizer")
    def test_returns_kdes_dict_and_raw_string(
        self, mock_get_model, _mock_lookup, _mock_parse
    ):
        # input_ids tensor: batch=1, seq_len=8
        input_ids = torch.zeros((1, 8), dtype=torch.long)

        mock_tokenizer = MagicMock()
        mock_tokenizer.apply_chat_template.return_value = "formatted chat"
        # tokenizer(text, ...) must return a dict with a real tensor so that
        # inputs["input_ids"].shape[-1] == 8 and **inputs can be unpacked
        mock_tokenizer.return_value = {"input_ids": input_ids}
        # model.generate returns a (1, 12) tensor; outputs[0].shape[0] = 12
        generated = torch.zeros((1, 12), dtype=torch.long)
        mock_model = MagicMock()
        mock_model.generate.return_value = generated
        # tokenizer.decode returns the raw LLM text
        mock_tokenizer.decode.return_value = "Audit Logging: 2.1.1"
        mock_get_model.return_value = (mock_tokenizer, mock_model)

        kdes, raw = extractor.extract_kdes_with_llm(
            "some document text",
            lambda text: "dummy prompt",
            "doc.pdf",
            output_dir=tempfile.gettempdir(),
        )

        self.assertIsInstance(kdes, dict)
        self.assertIsInstance(raw, str)
        self.assertIn("element1", kdes)
        self.assertEqual(kdes["element1"]["name"], "Audit Logging")


class TestCollectLlmOutputs(unittest.TestCase):
    """collect_llm_outputs writes prompt_type, llm_name, prompt, llm_output,
    and a separator for every result entry."""

    def test_output_file_contains_all_result_fields(self):
        results = [
            {
                "prompt_type": "zero-shot",
                "llm_name": "google/gemma-3-1b-it",
                "prompt": "Group these CIS EKS requirements",
                "llm_output": "Audit Logging: 2.1.1",
            }
        ]
        with tempfile.NamedTemporaryFile(
            mode="r", suffix=".txt", delete=False, encoding="utf-8"
        ) as tmp:
            tmp_path = tmp.name
        try:
            extractor.collect_llm_outputs(results, tmp_path)
            with open(tmp_path, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("zero-shot", content)
            self.assertIn("google/gemma-3-1b-it", content)
            self.assertIn("Group these CIS EKS requirements", content)
            self.assertIn("Audit Logging: 2.1.1", content)
            self.assertIn("---", content)
        finally:
            os.unlink(tmp_path)


# =============================================================================
# comparator.py
# =============================================================================

class TestLoadYaml(unittest.TestCase):
    """load_yaml correctly reads a well-formed YAML file and returns a dict
    whose contents match what was written."""

    def test_loads_valid_yaml_into_dict(self):
        data = {
            "element1": {
                "name": "Audit Logging",
                "requirements": ["2.1.1 Ensure audit logs"],
            },
            "element2": {
                "name": "RBAC",
                "requirements": ["4.1.1 Ensure RBAC is configured"],
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            yaml.dump(data, tmp)
            tmp_path = tmp.name
        try:
            result = comparator.load_yaml(tmp_path)
            self.assertIsInstance(result, dict)
            self.assertIn("element1", result)
            self.assertEqual(result["element1"]["name"], "Audit Logging")
        finally:
            os.unlink(tmp_path)


class TestDetectDifferencesNames(unittest.TestCase):
    """detect_differences_names returns a list that contains an entry for every
    name that exists in one dict but not the other, with the correct ABSENT/PRESENT labels."""

    def test_detects_name_present_only_in_first_file(self):
        data1 = {
            "element1": {"name": "Audit Logging",      "requirements": []},
            "element2": {"name": "RBAC Configuration", "requirements": []},
        }
        data2 = {
            "element1": {"name": "Audit Logging", "requirements": []},
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            comparator.detect_differences_names(data1, "file1.yaml", data2, "file2.yaml", tmp_dir)

            out_path = Path(tmp_dir) / Path("kde_name_diff.txt")
            self.assertTrue(out_path.exists(), "kde_name_diff.txt must be created")

            text = out_path.read_text(encoding="utf-8")
        
        self.assertTrue("RBAC Configuration" in text, "'RBAC Configuration' must appear as a difference")
        self.assertTrue("ABSENT-IN-file2.yaml" in text, "Missing name must be flagged as ABSENT in file2.yaml")


class TestDetectDifferencesRequirements(unittest.TestCase):
    """detect_differences_requirements returns a list entry for each requirement
    that exists in one element but is missing from the corresponding element in the other file."""

    def test_detects_requirement_present_only_in_first_file(self):
        data1 = {
            "element1": {
                "name": "Audit Logging",
                "requirements": [
                    "2.1.1 Ensure audit logs",
                    "2.1.2 Ensure log retention",   # <-- only in data1
                ],
            }
        }
        data2 = {
            "element1": {
                "name": "Audit Logging",
                "requirements": ["2.1.1 Ensure audit logs"],
            }
        } 
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            comparator.detect_differences_requirements(data1, "file1.yaml", data2, "file2.yaml", tmp_dir)

            out_path = Path(tmp_dir) / Path("kde_name_req_diff.txt")
            self.assertTrue(out_path.exists(), "kde_name_req_diff.txt must be created")

            text = out_path.read_text(encoding="utf-8")
        
        self.assertTrue("2.1.2 Ensure log retention" in text, "The requirement missing from data2 must appear in the differences")



# =============================================================================
# executor.py
# =============================================================================

class TestLoadText(unittest.TestCase):
    """load_text reads a .txt file and returns a list of non-empty, stripped lines."""

    def test_returns_stripped_lines_from_valid_file(self):
        content = (
            "LineA,ABSENT-IN-file2.yaml,PRESENT-IN-file1.yaml\n"
            "LineB,ABSENT-IN-file1.yaml,PRESENT-IN-file2.yaml\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            result = executor.load_text(tmp_path)
            self.assertEqual(result, [
                "LineA,ABSENT-IN-file2.yaml,PRESENT-IN-file1.yaml",
                "LineB,ABSENT-IN-file1.yaml,PRESENT-IN-file2.yaml",
            ])
        finally:
            os.unlink(tmp_path)


class TestDetectControls(unittest.TestCase):
    """detect_controls maps each KDE name to a Kubescape control ID and writes
    controls.txt, where every line contains an arrow and a C-XXXX control code."""

    def test_writes_control_mappings_to_controls_txt(self):
        # "Privileged container" is an exact name match for C-0057
        file_contents = [
            "Privileged container,ABSENT-IN-file2.yaml,PRESENT-IN-file1.yaml,NA",
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            executor.detect_controls(file_contents, tmp_dir)

            out_path = Path(tmp_dir) / "controls.txt"
            self.assertTrue(out_path.exists(), "controls.txt must be created")

            text = out_path.read_text(encoding="utf-8")
            self.assertIn("->", text)
            self.assertRegex(text, r"C-\d{4}")


class TestKubescapeScan(unittest.TestCase):
    """kubescape_scan calls subprocess.run with the expected arguments and returns
    a DataFrame built from the JSON results that kubescape writes to disk."""

    # Minimal kubescape JSON output structure
    _FAKE_RESULTS = {
        "results": [
            {
                "resourceID": "res-001",
                "controls": [
                    {
                        "controlID": "C-0057",
                        "name": "Privileged container",
                        "status": {"status": "failed"},
                        "severity": "High",
                    }
                ],
            }
        ],
        "summaryDetails": {
            "controls": {
                "C-0057": {
                    "ResourceCounters": {
                        "failedResources": 2,
                        "passedResources": 3,
                        "skippedResources": 0,
                    },
                    "complianceScore": 60,
                }
            }
        },
        "resources": [
            {
                "resourceID": "res-001",
                "source": {"relativePath": "deployment.yaml"},
            }
        ],
    }

    def test_returns_non_empty_dataframe_with_resource_id_column(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # controls.txt: last 7 chars of each line must be the control ID
            controls_path = Path(tmp_dir) / "controls.txt"
            controls_path.write_text(
                "Privileged container -> C-0057",
                encoding="utf-8",
            )
            results_json_path = Path(tmp_dir) / "kubescape-results.json"

            # Simulate kubescape writing its JSON output to disk
            def fake_run(cmd, **kwargs):
                results_json_path.write_text(
                    json.dumps(self._FAKE_RESULTS), encoding="utf-8"
                )
                return MagicMock(returncode=0)

            with patch("executor.subprocess.run", side_effect=fake_run):
                df = executor.kubescape_scan(
                    kubescape_path="kubescape",
                    control_map_path=controls_path,
                    cluster_path="/fake/cluster",
                    output_path=tmp_dir,
                )

            self.assertIsInstance(df, pandas.DataFrame)
            self.assertFalse(df.empty)
            self.assertIn("resourceID", df.columns)


class TestGenerateCsv(unittest.TestCase):
    """generate_csv creates resource_report.csv with the expected headers and
    one row per failed control, populated with stats from the JSON summary."""

    _FAKE_RESULTS = {
        "results": [
            {
                "resourceID": "res-001",
                "controls": [
                    {
                        "controlID": "C-0057",
                        "name": "Privileged container",
                        "status": {"status": "failed"},
                        "severity": "High",
                    }
                ],
            }
        ],
        "summaryDetails": {
            "controls": {
                "C-0057": {
                    "ResourceCounters": {
                        "failedResources": 2,
                        "passedResources": 3,
                        "skippedResources": 0,
                    },
                    "complianceScore": 60,
                }
            }
        },
        "resources": [
            {
                "resourceID": "res-001",
                "source": {"relativePath": "deployment.yaml"},
            }
        ],
    }

    def test_csv_headers_and_failed_row_content(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # generate_csv reads this file from disk
            json_path = Path(tmp_dir) / "kubescape-results.json"
            json_path.write_text(json.dumps(self._FAKE_RESULTS), encoding="utf-8")

            results_df = pandas.DataFrame(self._FAKE_RESULTS["results"])
            executor.generate_csv(results_df, tmp_dir)

            csv_path = Path(tmp_dir) / "resource_report.csv"
            self.assertTrue(csv_path.exists(), "resource_report.csv must be created")

            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            expected_headers = {
                "FilePath", "Severity", "Control name",
                "Failed resources", "All Resources", "Compliance score",
            }
            self.assertEqual(expected_headers, set(reader.fieldnames))
            self.assertEqual(len(rows), 1, "Exactly one failed-control row expected")
            self.assertEqual(rows[0]["FilePath"], "deployment.yaml")
            self.assertEqual(rows[0]["Control name"], "Privileged container")
            self.assertEqual(rows[0]["Compliance score"], "60%")

if __name__ == "__main__":
    unittest.main()